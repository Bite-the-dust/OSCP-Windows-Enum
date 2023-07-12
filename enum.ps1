function Write-Title{
    param([String]$Title)
    $splush = "`n" * 2 + ("#" * 50) + "`n" + "#" * [Math]::Floor((50 - $Title.Length - 2) / 2) + " "+ $Title + " " + "#" * [Math]::Ceiling((50 - $Title.Length - 2) / 2) + "`n" + ("#" * 50) + "`n"
    Write-Host -ForegroundColor Green $splush
}

function Enum-SystemInfo {
    Write-Title $MyInvocation.MyCommand.Name
    systeminfo
}

function Enum-UserInfo {
    Write-Title $MyInvocation.MyCommand.Name
    whoami /all
}

function Enum-LocalUsers {
    Write-Title $MyInvocation.MyCommand.Name
    $NonInterestingUserName = "Administrator,DefaultAccount,Guest,WDAGUtilityAccount"
    Get-LocalUser | Write-Host
}

function Enum-LocalGroups {
    Write-Title $MyInvocation.MyCommand.Name
    Get-LocalGroup | Write-Host
}

function Enum-NetworkInfo {
    #ipconfig /all
    #arp -a
    #route print

    Get-NetIPConfiguration | Select Ipv4Address
    Get-NetTCPConnection | ? { $_.State -eq "Listen" } | Sort-Object LocalPort
}

function Enum-InterestingFile {
    $Path = "C:\"
    $Include = "*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.config,*.ini"
    $Exclude = @("Program Files", "Program Files (x86)", "Program Data", "Windows")
    Get-ChildItem -Path $Path -Directory | ForEach-Object {
        if($Exclude -inotcontains $_.DirectoryName ){
            Get-ChildItem -Path $_.FullName -File -Recurse -Include $Include | Write-Host
        }
    }

    $SysPrepFiles = @("C:\unattend.xml","C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\Unattend\Unattend.xml","C:\Windows\system32\sysprep.inf","C:\Windows\system32\sysprep\sysprep.xml")
    $SysPrepFiles | ForEach-Object {
        if(Test-Path $_) { Get-Content $_ }
    }
}

function Enum-Service {
    $NonInterestingService = @("ActiveXInstaller(AxInstSV)","AgentActivationRuntime_2ccb4","AllJoynRouterService","AppReadiness","ApplicationIdentity","ApplicationInformation","ApplicationLayerGatewayService","ApplicationManagement","AppXDeploymentService(AppXSVC)","AssignedAccessManagerService","AutoTimeZoneUpdater","AVCTPservice","BackgroundIntelligentTransferService","BackgroundTasksInfrastructureService","BaseFilteringEngine","BitLockerDriveEncryptionService","BlockLevelBackupEngineService","BluetoothAudioGatewayService","BluetoothSupportService","BluetoothUserSupportService_2ccb4","BranchCache","CapabilityAccessManagerService","CaptureService_2ccb4","CellularTime","CertificatePropagation","ClientLicenseService(ClipSVC)","ClipboardUserService_2ccb4","CNGKeyIsolation","COM+EventSystem","COM+SystemApplication","ConnectedDevicesPlatformService","ConnectedDevicesPlatformUserService_2ccb4","ConnectedUserExperiencesandTelemetry","ConsentUX_2ccb4","ContactData_2ccb4","CoreMessaging","CredentialManager","CredentialEnrollmentManagerUserSvc_2ccb4","CryptographicServices","DataSharingService","DataUsage","DCOMServerProcessLauncher","DeliveryOptimization","DeviceAssociationService","DeviceInstallService","DeviceManagementEnrollmentService","DeviceManagementWirelessApplicationProtocol(WAP)PushmessageRoutingService","DeviceSetupManager","DeviceAssociationBroker_2ccb4","DevicePicker_2ccb4","DevicesFlow_2ccb4","DevQueryBackgroundDiscoveryBroker","DHCPClient","DiagnosticExecutionService","DiagnosticPolicyService","DiagnosticServiceHost","DiagnosticSystemHost","DisplayEnhancementService","DisplayPolicyService","DistributedLinkTrackingClient","DistributedTransactionCoordinator","DNSClient","DownloadedMapsManager","EmbeddedMode","EncryptingFileSystem(EFS)","EnterpriseAppManagementService","ExtensibleAuthenticationProtocol","Fax","FileHistoryService","FunctionDiscoveryProviderHost","FunctionDiscoveryResourcePublication","GameDVRandBroadcastUserService_2ccb4","GeolocationService","GraphicsPerfSvc","GroupPolicyClient","HumanInterfaceDeviceService","HVHostService","Hyper-VDataExchangeService","Hyper-VGuestServiceInterface","Hyper-VGuestShutdownService","Hyper-VHeartbeatService","Hyper-VPowerShellDirectService","Hyper-VRemoteDesktopVirtualizationService","Hyper-VTimeSynchronizationService","Hyper-VVolumeShadowCopyRequestor","IKEandAuthIPIPsecKeyingModules","InternetConnectionSharing(ICS)","IPHelper","IPTranslationConfigurationService","IPsecPolicyAgent","KtmRmforDistributedTransactionCoordinator","LanguageExperienceService","Link-LayerTopologyDiscoveryMapper","LocalProfileAssistantService","LocalSessionManager","MessagingService_2ccb4","Microsoft(R)DiagnosticsHubStandardCollectorService","MicrosoftAccountSign-inAssistant","MicrosoftApp-VClient","MicrosoftDefenderAntivirusNetworkInspectionService","MicrosoftDefenderAntivirusService","MicrosoftEdgeElevationService(MicrosoftEdgeElevationService)","MicrosoftEdgeUpdateService(edgeupdate)","MicrosoftEdgeUpdateService(edgeupdatem)","MicrosoftiSCSIInitiatorService","MicrosoftPassport","MicrosoftPassportContainer","MicrosoftSoftwareShadowCopyProvider","MicrosoftStorageSpacesSMP","MicrosoftStoreInstallService","MicrosoftWindowsSMSRouterService.","NaturalAuthentication","Net.TcpPortSharingService","Netlogon","NetworkConnectedDevicesAuto-Setup","NetworkConnectionBroker","NetworkConnections","NetworkConnectivityAssistant","NetworkListService","NetworkLocationAwareness","NetworkSetupService","NetworkStoreInterfaceService","OfflineFiles","OpenSSHAuthenticationAgent","Optimizedrives","ParentalControls","PaymentsandNFC/SEManager","PeerNameResolutionProtocol","PeerNetworkingGrouping","PeerNetworkingIdentityManager","PerformanceCounterDLLHost","PerformanceLogs&amp;Alerts","PhoneService","PlugandPlay","PNRPMachineNamePublicationService","PortableDeviceEnumeratorService","Power","PrintSpooler","PrinterExtensionsandNotifications","PrintWorkflow_2ccb4","ProblemReportsControlPanelSupport","ProgramCompatibilityAssistantService","QualityWindowsAudioVideoExperience","RadioManagementService","RecommendedTroubleshootingService","RemoteAccessAutoConnectionManager","RemoteAccessConnectionManager","RemoteDesktopConfiguration","RemoteDesktopServices","RemoteDesktopServicesUserModePortRedirector","RemoteProcedureCall(RPC)","RemoteProcedureCall(RPC)Locator","RemoteRegistry","RetailDemoService","RoutingandRemoteAccess","RPCEndpointMapper","SecondaryLogon","SecureSocketTunnelingProtocolService","SecurityAccountsManager","SecurityCenter","SensorDataService","SensorMonitoringService","SensorService","Server","SharedPCAccountManager","ShellHardwareDetection","SmartCard","SmartCardDeviceEnumerationService","SmartCardRemovalPolicy","SNMPTrap","SoftwareProtection","SpatialDataService","SpotVerifier","SSDPDiscovery","StateRepositoryService","StillImageAcquisitionEvents","StorageService","StorageTiersManagement","SyncHost_2ccb4","SysMain","SystemEventNotificationService","SystemEventsBroker","SystemGuardRuntimeMonitorBroker","TaskScheduler","TCP/IPNetBIOSHelper","Telephony","Themes","TimeBroker","TouchKeyboardandHandwritingPanelService","UdkUserService_2ccb4","UpdateOrchestratorService","UPnPDeviceHost","UserDataAccess_2ccb4","UserDataStorage_2ccb4","UserExperienceVirtualizationService","UserManager","UserProfileService","VirtualDisk","VirtualBoxGuestAdditionsService","VolumeShadowCopy","VolumetricAudioCompositorService","WalletService","WarpJITSvc","WebAccountManager","WebClient","Wi-FiDirectServicesConnectionManagerService","WindowsAudio","WindowsAudioEndpointBuilder","WindowsBackupWindowsBiometricService","WindowsCameraFrameServer","WindowsConnectNow-ConfigRegistrar","WindowsConnectionManager","WindowsDefenderAdvancedThreatProtectionService","WindowsDefenderFirewall","WindowsEncryptionProviderHostService","WindowsErrorReportingService","WindowsEventCollector","WindowsEventLog","WindowsFontCacheService","WindowsImageAcquisition(WIA)","WindowsInsiderService","WindowsInstaller","WindowsLicenseManagerService","WindowsManagementInstrumentation","WindowsManagementService","WindowsMediaPlayerNetworkSharingService","WindowsMixedRealityOpenXRService","WindowsMobileHotspotService","WindowsModulesInstaller","WindowsPerceptionService","WindowsPerceptionSimulationService","WindowsPushNotificationsSystemService","WindowsPushNotificationsUserService_2ccb4","WindowsPushToInstallService","WindowsRemoteManagement(WS-Management)","WindowsSearch","WindowsSecurityService","WindowsTime","WindowsUpdate","WindowsUpdateMedicService","WinHTTPWebProxyAuto-DiscoveryService","WiredAutoConfig","WLANAutoConfig","WMIPerformanceAdapter","WorkFolders","Workstation","WWANAutoConfig","XboxAccessoryManagementService","XboxLiveAuthManager","XboxLiveGameSave","XboxLiveNetworkingService")
    Get-Service | ForEach-Object {
        if($NonInterestingService -inotcontains $_.DisplayName.Replace(" ","")) {
            Write-Host $_
        }
    }
}

function Invoke-AllChecks {
    Enum-SystemInfo
    Enum-UserInfo
    Enum-LocalUsers
    Enum-LocalGroups
    Enum-NetworkInfo
}
