/*
 * Copyright (C) 2021 - 2023, SanteSuite Inc. and the SanteSuite Contributors (See NOTICE.md for full copyright notices)
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
 * User: fyfej
 * Date: 2023-5-19
 */
using SanteDB.Core.Diagnostics;
using SanteDB.Messaging.HL7.Configuration;

/*
 * Copyright 2012-2013 Mohawk College of Applied Arts and Technology
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
 * User: fyfej
 * Date: 13-8-2012
 */

using System;
using System.ComponentModel;
using System.Diagnostics.Tracing;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace SanteDB.Messaging.HL7.TransportProtocol
{
    /// <summary>
    /// Transport protocol for TCP
    /// </summary>
    [Description("ER7 over TCP")]
    public class TcpTransport : ITransportProtocol
    {
        /// <summary>
        /// Diagnostic tracer.
        /// </summary>
        protected readonly Tracer m_traceSource = new Tracer(Hl7Constants.TraceSourceName);

        #region ITransportProtocol Members

        // The socket
        private TcpListener m_listener;

        // Will run while true
        private bool m_run = true;

        /// <summary>
        /// Message has been received
        /// </summary>
        public event EventHandler<Hl7MessageReceivedEventArgs> MessageReceived;

        /// <summary>
        /// An enumeration of valid bytes
        /// </summary>
        public enum ByteType : byte
        {
            /// <summary>
            /// End of transmission
            /// </summary>
            EOT = 0x04,
            /// <summary>
            /// Equiry
            /// </summary>
            ENQ = 0x05,
            /// <summary>
            /// Acknowledge
            /// </summary>
            ACK = 0x06,
            /// <summary>
            /// Bell
            /// </summary>
            BEL = 0x07,
            /// <summary>
            /// Backspace
            /// </summary>
            BS = 0x08,
            /// <summary>
            /// Tab
            /// </summary>
            TAB = 0x09,
            /// <summary>
            /// Line feed
            /// </summary>
            LF = 0x0a,
            /// <summary>
            /// Vertical Tab
            /// </summary>
            VTAB = 0x0b,
            /// <summary>
            /// Carriage return
            /// </summary>
            CR = (byte)'\r',
            /// <summary>
            /// Negative Ack
            /// </summary>
            NACK = 0x15,
            /// <summary>
            /// End of file
            /// </summary>
            EOF = 0x1a,
            /// <summary>
            /// Escape
            /// </summary>
            ESC = 0x1b,
            /// <summary>
            /// File Separator
            /// </summary>
            FS = 0x1c
        }

        /// <summary>
        /// Gets the name of the protocol
        /// </summary>
        public string ProtocolName
        {
            get { return "tcp"; }
        }

        /// <summary>
        /// Setup configuration
        /// </summary>
        public void SetupConfiguration(Hl7ServiceDefinition definition)
        {
        }

        /// <summary>
        /// Start the handler
        /// </summary>
        public void Start(IPEndPoint bind, ServiceHandler handler)
        {
            this.m_listener = new TcpListener(bind);
            this.m_listener.Start();
            this.m_traceSource.TraceInfo("TCP Transport bound to {0}", bind);

            while (m_run) // run the service
            {
                // Client
                TcpClient client = this.m_listener.AcceptTcpClient();
                Thread clientThread = new Thread(ReceiveMessage);
                clientThread.IsBackground = true;
                clientThread.Start(client);
            }
        }

        /// <summary>
        /// Stop the thread
        /// </summary>
        public void Stop()
        {
            this.m_run = false;
            this.m_listener.Stop();
            this.m_traceSource.TraceInfo("TCP Transport stopped");
        }

        /// <summary>
        /// Receive and process message
        /// </summary>
        private void ReceiveMessage(object client)
        {
            TcpClient tcpClient = client as TcpClient;
            NetworkStream stream = tcpClient.GetStream();
            try
            {
                // Now read to a string
                NHapi.Base.Parser.PipeParser parser = new NHapi.Base.Parser.PipeParser();

                StringBuilder messageData = new StringBuilder();
                byte[] buffer = new byte[1024];
                while (stream.DataAvailable)
                {
                    int br = stream.Read(buffer, 0, 1024);
                    messageData.Append(Encoding.ASCII.GetString(buffer, 0, br));
                }

                var message = parser.Parse(messageData.ToString());
                var localEp = tcpClient.Client.LocalEndPoint as IPEndPoint;
                var remoteEp = tcpClient.Client.RemoteEndPoint as IPEndPoint;
                Uri localEndpoint = new Uri(String.Format("tcp://{0}:{1}", localEp.Address, localEp.Port));
                Uri remoteEndpoint = new Uri(String.Format("tcp://{0}:{1}", remoteEp.Address, remoteEp.Port));
                var messageArgs = new Hl7MessageReceivedEventArgs(message, localEndpoint, remoteEndpoint, DateTime.Now);
                HL7OperationContext.Current = new HL7OperationContext(messageArgs);

                this.MessageReceived(this, messageArgs);

                // Send the response back
                StreamWriter writer = new StreamWriter(stream);
                if (messageArgs.Response != null)
                {
                    writer.Write(parser.Encode(messageArgs.Response));
                    writer.Flush();
                }
            }
            catch (Exception e)
            {
                this.m_traceSource.TraceEvent(EventLevel.Error, e.ToString());
                // TODO: NACK
            }
            finally
            {
                stream.Close();
                HL7OperationContext.Current = null;
            }
        }

        #endregion ITransportProtocol Members
    }
}