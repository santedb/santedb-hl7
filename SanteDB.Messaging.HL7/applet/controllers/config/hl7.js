/*
 * Copyright (C) 2021 - 2021, SanteSuite Inc. and the SanteSuite Contributors (See NOTICE.md for full copyright notices)
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
 * Date: 2021-8-5
 */
angular.module('santedb').controller('HL7ConfigurationController', ['$scope', '$rootScope', function ($scope, $rootScope) {
    
    // Watch the configuration
    $scope.$parent.$watch("config", function(n, o) {
        if(n) {
            $scope.config = n;
            $scope.hl7Config = $scope.config.others.find(function(s) {
                return s.$type == "SanteDB.Messaging.HL7.Configuration.Hl7ConfigurationSection, SanteDB.Messaging.HL7";
            });

            if($scope.hl7Config)
                delete($scope.hl7Config.localAuthority.$type);
        }
    });
    
    $scope.$parent.$watch("config.sync.subscribe", function(n, o) {
        if(n && $scope.hl7Config) {
            $scope.hl7Config.facility = n[0];
        }
    })
    
}]);