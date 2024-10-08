﻿/*
 * Copyright (C) 2021 - 2024, SanteSuite Inc. and the SanteSuite Contributors (See NOTICE.md for full copyright notices)
 * Copyright (C) 2019 - 2021, Fyfe Software Inc. and the SanteSuite Contributors
 * Portions Copyright (C) 2015-2018 Mohawk College of Applied Arts and Technology
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you 
 * may not use this file except in compliance with the License. You may 
 * obtain a copy of the License at 
 * 
 * http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the 
 * License for the specific language governing permissions and limitations under 
 * the License.
 * 
 */
using NHapi.Base.Parser;
using SanteDB.Core;
using SanteDB.Core.Diagnostics;
using SanteDB.Core.Security.Audit;
using SanteDB.Core.Services;
using SanteDB.Messaging.HL7.Utils;
using System;
using System.ComponentModel;
using System.Diagnostics.Tracing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
#pragma warning disable CS0612

namespace SanteDB.Messaging.HL7.TransportProtocol
{
    /// <summary>
    /// HL7 llp transport
    /// </summary>
    [Description("ER7 over LLP")]
    public class LlpTransport : ITransportProtocol
    {
        /// <summary>
        /// Logging provider.
        /// </summary>
        protected readonly Tracer m_traceSource = new Tracer(Hl7Constants.TraceSourceName);


        /// <summary>
        /// Start transmission
        /// </summary>
        public const byte START_TX = 0x0b;

        /// <summary>
        /// End transmission
        /// </summary>
        public const byte END_TX = 0x1c;

        /// <summary>
        /// End transmission line
        /// </summary>
        public const byte END_TXNL = (byte)'\r';

        #region ITransportProtocol Members

        /// <summary>
        /// Timeout
        /// </summary>
        protected TimeSpan m_timeout;

        /// <summary>
        /// The socket
        /// </summary>
        protected TcpListener m_listener;

        /// <summary>
        /// Set to false to end the listener process.
        /// </summary>
        protected bool m_run = true;

        /// <summary>
        /// Gets the name of the protocol
        /// </summary>
        public virtual string ProtocolName
        {
            get { return "llp"; }
        }

        /// <summary>
        /// Start the transport
        /// </summary>
        public virtual void Start(IPEndPoint bind, ServiceHandler handler)
        {
            this.m_timeout = new TimeSpan(0, 0, 0, handler.Definition.ReceiveTimeout);
            this.m_listener = new TcpListener(bind);

            this.m_listener.Start();
            this.m_traceSource.TraceInfo("LLP Transport bound to {0}", bind);
            var threadPool = ApplicationServiceContext.Current.GetService<IThreadPoolService>();

            while (m_run) // run the service
            {
                try
                {
                    var socketAccept = this.m_listener.BeginAcceptTcpClient((o) =>
                    {
                        if (this.m_listener.Server?.IsBound == true)
                        {
                            threadPool.QueueUserWorkItem(OnReceiveMessage, this.m_listener.EndAcceptTcpClient(o));
                        }
                    }, null);
                    socketAccept.AsyncWaitHandle.WaitOne(handler.Definition.ReceiveTimeout);
                }
                catch (Exception e)
                {
                    if (this.m_run)
                    {
                        this.m_traceSource.TraceEvent(EventLevel.Error, "Error on HL7 worker {0} - {1}", this.m_listener.LocalEndpoint, e);
                    }
                }
            }
        }

        /// <summary>
        /// Receive and process message
        /// </summary>
        protected virtual void OnReceiveMessage(object client)
        {
            using (TcpClient tcpClient = client as TcpClient)
            {
                this.m_traceSource.TraceEvent(EventLevel.Verbose, "Accepted connection on {0} from {1}", this.m_listener.LocalEndpoint, tcpClient.Client.RemoteEndPoint);
                NetworkStream stream = tcpClient.GetStream();
                try
                {
                    // Now read to a string
                    DateTime lastReceive = DateTime.Now;

                    while (DateTime.Now.Subtract(lastReceive) < this.m_timeout)
                    {
                        if (!stream.DataAvailable)
                        {
                            Thread.Sleep(10);
                            continue;
                        }

                        // Read LLP head byte
                        int llpByte = stream.ReadByte();
                        if (llpByte != START_TX) // first byte must be HT
                        {
                            throw new InvalidOperationException("Invalid LLP First Byte");
                        }

                        // Standard stream stuff, read until the stream is exhausted
                        StringBuilder messageData = new StringBuilder();
                        byte[] buffer = new byte[1024];
                        bool receivedEOF = false, scanForCr = false;

                        while (!receivedEOF)
                        {
                            if (DateTime.Now.Subtract(lastReceive) > this.m_timeout)
                            {
                                throw new TimeoutException("Data not received in the specified amount of time. Increase the timeout or check the network connection");
                            }

                            if (!stream.DataAvailable)
                            {
                                Thread.Sleep(10);
                                continue;
                            }

                            int br = stream.Read(buffer, 0, 1024);
                            messageData.Append(System.Text.Encoding.UTF8.GetString(buffer, 0, br));

                            // Need to check for CR?
                            if (scanForCr)
                            {
                                receivedEOF = buffer[0] == END_TXNL;
                            }
                            else
                            {
                                // Look for FS
                                int fsPos = Array.IndexOf(buffer, (byte)END_TX);

                                if (fsPos == -1) // not found
                                {
                                    continue;
                                }
                                else if (fsPos < buffer.Length - 1) // more room to read
                                {
                                    receivedEOF = buffer[fsPos + 1] == END_TXNL;
                                }
                                else
                                {
                                    scanForCr = true; // Cannot check the end of message for CR because there is no more room in the message buffer
                                }
                                // so need to check on the next loop
                            }
                        }

                        // Use the nHAPI parser to process the data
                        Hl7MessageReceivedEventArgs messageArgs = null;
                        String originalVersion = null;

                        // Setup local and remote receive endpoint data for auditing
                        var localEp = tcpClient.Client.LocalEndPoint as IPEndPoint;
                        var remoteEp = tcpClient.Client.RemoteEndPoint as IPEndPoint;
                        Uri localEndpoint = new Uri(String.Format("llp://{0}:{1}", localEp.Address, localEp.Port));
                        Uri remoteEndpoint = new Uri(String.Format("llp://{0}:{1}", remoteEp.Address, remoteEp.Port));

                        foreach (var messagePart in messageData.ToString().Split((char)END_TX))
                        {
                            if (messagePart == "\r")
                            {
                                continue;
                            }

                            try
                            {
                                this.m_traceSource.TraceInfo("Received message from llp://{0}:{1} : {2}", remoteEp.Address, remoteEp.Port, messagePart);
                                // HACK: nHAPI doesn't like URLs ... Will fix this later
                                string messageString = messagePart.Replace("|URL|", "|ST|");

                                var message = MessageUtils.ParseMessage(messageString, out originalVersion);
                                messageArgs = new Hl7MessageReceivedEventArgs(message, localEndpoint, remoteEndpoint, DateTime.Now);

                                HL7OperationContext.Current = new HL7OperationContext(messageArgs);

                                // Call any bound event handlers that there is a message available
                                OnMessageReceived(messageArgs);
                            }
                            catch (Exception e)
                            {
                                this.m_traceSource.TraceError("Error processing HL7 message: {0}", e);
                                var auditservice = ApplicationServiceContext.Current.GetAuditService();
                                if (messageArgs != null)
                                {
                                    var nack = new NHapi.Model.V25.Message.ACK();
                                    nack.MSH.SetDefault(messageArgs.Message.GetStructure("MSH") as NHapi.Model.V25.Segment.MSH);
                                    nack.MSA.AcknowledgmentCode.Value = "AE";
                                    nack.MSA.TextMessage.Value = $"FATAL - {e.Message}";
                                    nack.MSA.MessageControlID.Value = (messageArgs.Message.GetStructure("MSH") as NHapi.Model.V25.Segment.MSH).MessageControlID.Value;
                                    messageArgs.Response = nack;

                                    var icomps = PipeParser.Encode(messageArgs.Message.GetStructure("MSH") as NHapi.Base.Model.ISegment, new EncodingCharacters('|', "^~\\&")).Split('|');
                                    var ocomps = PipeParser.Encode(messageArgs.Response.GetStructure("MSH") as NHapi.Base.Model.ISegment, new EncodingCharacters('|', "^~\\&")).Split('|');
                                    auditservice.Audit().ForNetworkRequestFailure(e, messageArgs.ReceiveEndpoint, Enumerable.Range(1, icomps.Length).ToDictionary(o => $"MSH-{o}", o => icomps[o - 1]), Enumerable.Range(1, icomps.Length).ToDictionary(o => $"MSH-{o}", o => ocomps[o - 1])).Send();
                                }
                                else
                                {
                                    auditservice.Audit().ForNetworkRequestFailure(e, localEndpoint, new System.Collections.Specialized.NameValueCollection(), new System.Collections.Specialized.NameValueCollection()).Send();
                                }
                            }
                            finally
                            {
                                // Send the response back
                                using (MemoryStream memoryWriter = new MemoryStream())
                                {
                                    using (StreamWriter streamWriter = new StreamWriter(memoryWriter))
                                    {
                                        memoryWriter.Write(new byte[] { START_TX }, 0, 1); // header
                                        if (messageArgs != null && messageArgs.Response != null)
                                        {
                                            var strMessage = MessageUtils.EncodeMessage(messageArgs.Response, originalVersion);
                                            this.m_traceSource.TraceInfo("Sending message to llp://{0} : {1}", tcpClient.Client.RemoteEndPoint, strMessage);
                                            // Since nHAPI only emits a string we just send that along the stream
                                            streamWriter.Write(strMessage);
                                            streamWriter.Flush();
                                        }
                                        memoryWriter.Write(new byte[] { END_TX, END_TXNL }, 0, 2); // Finish the stream with FSCR
                                        stream.Write(memoryWriter.ToArray(), 0, (int)memoryWriter.Position);
                                        stream.Flush();
                                    }
                                }
                                lastReceive = DateTime.Now; // Update the last receive time so the timeout function works
                            }
                        }

                        if (!stream.DataAvailable)
                        {
                            return;
                        }
                    }
                }
                catch (Exception e)
                {
                    this.m_traceSource.TraceEvent(EventLevel.Error, e.ToString());
                }
                finally
                {
                    stream.Close();
                    tcpClient.Close();
                    HL7OperationContext.Current = null;
                }
            }
        }

        /// <summary>
        /// Message received
        /// </summary>
        /// <param name="messageArgs">The received message arguments</param>
        protected void OnMessageReceived(Hl7MessageReceivedEventArgs messageArgs)
        {
            if (this.MessageReceived != null)
            {
                this.MessageReceived(this, messageArgs);
            }
        }

        /// <summary>
        /// Stop the thread
        /// </summary>
        public void Stop()
        {
            this.m_run = false;
            this.m_listener.Stop();

            this.m_traceSource.TraceInfo("LLP Transport stopped");
        }

        /// <summary>
        /// Message has been received
        /// </summary>
        public event EventHandler<Hl7MessageReceivedEventArgs> MessageReceived;

        #endregion ITransportProtocol Members
    }
}
#pragma warning restore