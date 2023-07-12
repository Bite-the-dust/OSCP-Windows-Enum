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

function Invoke-AllChecks {
    Enum-SystemInfo
    Enum-UserInfo
    Enum-LocalUsers
    Enum-LocalGroups
    Enum-NetworkInfo
}
