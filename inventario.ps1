#$ErrorActionPreference = "SilentlyContinue"
                $StrComputer = $env:COMPUTERNAME
                if(!([Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $StrComputer))){
                cmd /c sc \\$StrComputer config remoteregistry start= auto

                cmd /c sc \\$StrComputer start remoteregistry
                }
                Function Get-RemoteProgram {
                    [CmdletBinding(SupportsShouldProcess=$true)]
                    param(
                        [Parameter(ValueFromPipeline              =$true,
                                   ValueFromPipelineByPropertyName=$true,
                                   Position=0
                        )]
                        [string[]]
                            $ComputerName = $env:COMPUTERNAME,
                        [Parameter(Position=0)]
                        [string[]]
                            $Property,
                        [switch]
                            $ExcludeSimilar,
                        [int]
                            $SimilarWord
                    )

                    begin {
                        $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
                                            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'
                        $HashProperty = @{}
                        $SelectProperty = @('ProgramName','ComputerName')
                        if ($Property) {
                            $SelectProperty += $Property
                        }
                    }

                    process {
                        foreach ($Computer in $ComputerName) {
                            $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)
                            $RegistryLocation | ForEach-Object {
                                $CurrentReg = $_
                                if ($RegBase) {
                                    $CurrentRegKey = $RegBase.OpenSubKey($CurrentReg)
                                    if ($CurrentRegKey) {
                                        $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                                            if ($Property) {
                                                foreach ($CurrentProperty in $Property) {
                                                    $HashProperty.$CurrentProperty = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue($CurrentProperty)
                                                }
                                            }
                                            $HashProperty.ComputerName = $Computer
                                            $HashProperty.ProgramName = ($DisplayName = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('DisplayName'))
                                            if ($DisplayName) {
                                                New-Object -TypeName PSCustomObject -Property $HashProperty |
                                                Select-Object -Property $SelectProperty
                                            }
                                        }
                                    }
                                }
                            } | ForEach-Object -Begin {
                                if ($SimilarWord) {
                                    $Regex = [regex]"(^(.+?\s){$SimilarWord}).*$|(.*)"
                                } else {
                                    $Regex = [regex]"(^(.+?\s){3}).*$|(.*)"
                                }
                                [System.Collections.ArrayList]$Array = @()
                            } -Process {
                                if ($ExcludeSimilar) {
                                    $null = $Array.Add($_)
                                } else {
                                    $_
                                }
                            } -End {
                                if ($ExcludeSimilar) {
                                    $Array | Select-Object -Property *,@{
                                        name       = 'GroupedName'
                                        expression = {
                                            ($_.ProgramName -split $Regex)[1]
                                        }
                                    } |
                                    Group-Object -Property 'GroupedName' | ForEach-Object {
                                        $_.Group[0] | Select-Object -Property * -ExcludeProperty GroupedName
                                    }
                                }
                            }
                        }
                    }
                }

                 $apptotal=@()
                $command = (Get-RemoteProgram -computername $StrComputer -Property Publisher,InstallDate,DisplayVersion,InstallSource,IsMinorUpgrade,ReleaseType,ParentDisplayName,SystemComponent | Where-Object {[string]$_.SystemComponent -ne 1 -and ![string]$_.IsMinorUpgrade -and ![string]$_.ReleaseType -and ![string]$_.ParentDisplayName} | Sort-Object ProgramName | Select-Object -ExpandProperty ProgramName )
                $apps = $command | sort -unique
                $apptotal+=$strcomputer | Out-String
                $apptotal+=$apps


                $GenItems1 = gwmi Win32_ComputerSystem -Comp $StrComputer
                $GenItems2 = gwmi Win32_OperatingSystem -Comp $StrComputer
                $SysItems1 = gwmi Win32_BIOS -Comp $StrComputer
                $SysItems2 = gwmi Win32_TimeZone -Comp $StrComputer
                $SysItems3 = gwmi Win32_WmiSetting -Comp $StrComputer
                $ProcItems1 = gwmi Win32_Processor -Comp $StrComputer
                $MemItems1 = gwmi Win32_PhysicalMemory -Comp $StrComputer
                $memItems2 = gwmi Win32_PhysicalMemoryArray -Comp $StrComputer
                $DiskItems = gwmi Win32_LogicalDisk -Comp $StrComputer
                $NetItems = gwmi Win32_NetworkAdapterConfiguration -Comp $StrComputer |`
                where{$_.IPEnabled -eq "True"}
                                     $computer = $StrComputer

                                     $isLaptop = $false
                                     if(Get-WmiObject -Class win32_systemenclosure -ComputerName $computer |
                                        Where-Object { $_.chassistypes -eq 9 -or $_.chassistypes -eq 10 `
                                        -or $_.chassistypes -eq 14})
                                       { $isLaptop = $true }
                                     if(Get-WmiObject -Class win32_battery -ComputerName $computer)
                                       { $isLaptop = $true }
                                     If($isLaptop) { $tipo="Portatil" }
                                    else { $tipo="Escritorio"}






                            $line = echo $GenItems1.Name



                                        $velocidad = $ProcItems1.name
                                        $velocidad = $velocidad.Substring($velocidad.get_Length()-8)
                                        $computer = $StrComputer

                                         $PhysicalRAM = (Get-WMIObject -class Win32_PhysicalMemory -ComputerName $Computer |
                                        Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)})

                                        $memoria = -join $PhysicalRAM + " " + "GB"


                                             $disco=Get-WmiObject Win32_DiskDrive -computername $StrComputer |  Where-Object -FilterScript {$_.DeviceID -Eq "\\.\PHYSICALDRIVE0"}  |
                                             Measure-Object -Property size -Sum | % {[Math]::Round(($_.sum / 1GB))}
                                             $lookupTable = @{
                                                            "119" = "128 GB"
                                                            "149" = "160 GB"
                                                            "699" = "720 GB"

                                                            "298" = "320 GB"
                                                            "932" = "1 TB"
                                                            "466" = "500 GB"
                                                             }


                                                         $lookupTable.GetEnumerator() | ForEach-Object {
                                                         if ($disco -match $_.Key)
                                                            {
                                                            $disco = $disco -replace $_.Key, $_.Value
                                                            }
                                                                                                        }

                  $ManufacturerHash = @{
                    "AAC" = "AcerView";
                    "ACR" = "Acer";
                    "AOC" = "AOC";
                    "AIC" = "AG Neovo";
                    "APP" = "Apple Computer";
                    "AST" = "AST Research";
                    "AUO" = "Equipo Portatil";
                    "BNQ" = "BenQ";
                    "CMO" = "Acer";
                    "CPL" = "Compal";
                    "CPQ" = "Compaq";
                    "CPT" = "Chunghwa Pciture Tubes, Ltd.";
                    "CTX" = "CTX";
                    "DEC" = "DEC";
                    "DEL" = "Dell";
                    "DPC" = "Delta";
                    "DWE" = "Daewoo";
                    "EIZ" = "EIZO";
                    "ELS" = "ELSA";
                    "ENC" = "EIZO";
                    "EPI" = "Envision";
                    "FCM" = "Funai";
                    "FUJ" = "Fujitsu";
                    "FUS" = "Fujitsu-Siemens";
                    "GSM" = "LG Electronics";
                    "GWY" = "Gateway 2000";
                    "HEI" = "Hyundai";
                    "HIT" = "Hyundai";
                    "HSL" = "Hansol";
                    "HTC" = "Hitachi/Nissei";
                    "HWP" = "HP";
                    "IBM" = "IBM";
                    "ICL" = "Fujitsu ICL";
                    "IVM" = "Iiyama";
                    "KDS" = "Korea Data Systems";
                    "LEN" = "Lenovo";
                    "LGD" = "Asus";
                    "LPL" = "Fujitsu";
                    "MAX" = "Belinea";
                    "MEI" = "Panasonic";
                    "MEL" = "Mitsubishi Electronics";
                    "MS_" = "Panasonic";
                    "NAN" = "Nanao";
                    "NEC" = "NEC";
                    "NOK" = "Nokia Data";
                    "NVD" = "Fujitsu";
                    "OPT" = "Optoma";
                    "PHL" = "Philips";
                    "REL" = "Relisys";
                    "SAN" = "Samsung";
                    "SAM" = "Samsung";
                    "SBI" = "Smarttech";
                    "SGI" = "SGI";
                    "SNY" = "Sony";
                    "SRC" = "Shamrock";
                    "SUN" = "Sun Microsystems";
                    "SEC" = "Hewlett-Packard";
                    "TAT" = "Tatung";
                    "TOS" = "Toshiba";
                    "TSB" = "Toshiba";
                    "VSC" = "ViewSonic";
                    "ZCM" = "Zenith";
                    "UNK" = "Unknown";
                    "_YV" = "Fujitsu";
                      }




                    $Monitors = Get-WmiObject -Namespace "root\WMI" -Class "WMIMonitorID" -ComputerName $Computer -ErrorAction SilentlyContinue

                    $Monitor_Array = @()


                    ForEach ($Monitor in $Monitors) {

                      If ([System.Text.Encoding]::ASCII.GetString($Monitor.UserFriendlyName) -ne $null) {
                        $Mon_Model = ([System.Text.Encoding]::ASCII.GetString($Monitor.UserFriendlyName)).Replace("$([char]0x0000)","")
                      } else {
                        $Mon_Model = $null
                      }
                      $Mon_Serial_Number = ([System.Text.Encoding]::ASCII.GetString($Monitor.SerialNumberID)).Replace("$([char]0x0000)","")
                      $Mon_Attached_Computer = ($Monitor.PSComputerName).Replace("$([char]0x0000)","")
                      $Mon_Manufacturer = ([System.Text.Encoding]::ASCII.GetString($Monitor.ManufacturerName)).Replace("$([char]0x0000)","")

                      If ($Mon_Model -like "*800 AIO*" -or $Mon_Model -like "*8300 AiO*") {Break}

                      $Mon_Manufacturer_Friendly = $ManufacturerHash.$Mon_Manufacturer
                      If ($Mon_Manufacturer_Friendly -eq $null) {
                        $Mon_Manufacturer_Friendly = $Mon_Manufacturer
                      }

                      $Monitor_Obj = [PSCustomObject]@{
                        Manufacturer     = $Mon_Manufacturer_Friendly
                        Model            = $Mon_Model
                        SerialNumber     = $Mon_Serial_Number
                        AttachedComputer = $Mon_Attached_Computer
                      }

                      $Monitor_Array += $Monitor_Obj

                    }


                cedula=""
                $strSID=""
                $Name=""
                  $osversion=[Environment]::OSVersion.Version
                  $windows = New-Object -Type PSObject |
                             Add-Member -MemberType NoteProperty -Name Caption -Value (Get-WmiObject -Class Win32_OperatingSystem).Caption -PassThru |
                             Add-Member -MemberType NoteProperty -Name Version -Value $osversion           -PassThru  
                  $version_sistema_operativo=  "{0} {1} {2}" -f $windows.Version, "Compilacion", $osversion.Build
                
                  
                  
                  
                 function getusername {
                   $Days='20'
                   $events = @()
                   $events += Get-WinEvent  -FilterHashtable @{
                   LogName='Security'
                   Id=@(4800,4801)
                   StartTime=(Get-Date).AddDays(-$Days)
                      }
                   $events += Get-WinEvent  -FilterHashtable @{
                   LogName='System'
                   Id=@(7000,7001)
                   StartTime=(Get-Date).AddDays(-$Days)
                     }

                   $type_lu = @{
                    7001 = 'Logon'
                    7002 = 'Logoff'
                    4800 = 'Lock'
                    4801 = 'UnLock'
                     }

                   $ns = @{'ns'="http://schemas.microsoft.com/win/2004/08/events/event"}
                   $target_xpath = "//ns:Data[@Name='TargetUserName']"
                   $usersid_xpath = "//ns:Data[@Name='UserSid']"

                   If($events) {
                   $results = ForEach($event in $events) {
                   $xml = $event.ToXml()
                   Switch -Regex ($event.Id) {
                    '4...' {
                   $user = (
                     Select-Xml -Content $xml -Namespace $ns -XPath $target_xpath
                   ).Node.'#text'
                   Break
                   }
                   '7...' {
                   $sid = (
                    Select-Xml -Content $xml -Namespace $ns -XPath $usersid_xpath
                   ).Node.'#text'
                   $user = (
                    New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList $sid
                   ).Translate([System.Security.Principal.NTAccount]).Value
                   Break
                   }
                   }
                   New-Object -TypeName PSObject -Property @{
                   Time = $event.TimeCreated
                    Id = $event.Id
                   Type = $type_lu[$event.Id]
                   User = $user
                     }
                      }
                    If($results) {

                   ($Results | Sort Time -Descending ).user | Select-Object -first 1
                    }
                    }
                    }

                    $strSID = getusername
                    if ($strSID.count  -eq 0){ $strSID =Get-WmiObject -Class Win32_Process -Filter "Name = 'explorer.exe'" |
                    ForEach-Object { $_.GetOwner() | % { "$($_.Domain)\$($_.User)" } } |
                    Sort-Object -Unique }
                    $strSID = $strSID.split("\") | select-object -last 1



                 $fecha=Get-Date -format dd-MMMM-yyyy
                 Switch($GenItems1.DomainRole)
                {
                0{$comunicacion= "Stand Alone Workstation"}
                1{$comunicacion= "Member Workstation"}
                2{$comunicacion= "Stand Alone Server"}
                3{$comunicacion= "Member Server"}
                4{$comunicacion= "Back-up Domain Controller"}
                5{$comunicacion= "Primary Domain Controller"}
                default{$comunicacion="Undetermined Domain Role"}
                }
               
                $apptotal2 = ( $apptotal | ConvertTo-Json )

                $apptotal2= $apptotal2.Replace("\r\n","")
                
                $item= @{
                usurario=$strSID
                type=$tipo
                nombreequipo=$GenItems1.Name
                brand=$GenItems1.Manufacturer
                model=$GenItems1.Model
                ramMemory=$memoria
                hardDisk=$disco
                sistemaoperativo=$GenItems2.Caption
                procesador=$ProcItems1.Name
                serie=$SysItems1.SerialNumber
                netdesc=$NetItems.description[0]
                mac=$NetItems.MACAddress[0]
                ip=$NetItems.IPAddress[0]
                monitor=$Monitor_Array.manufacturer
                monitorodel=$Monitor_Array.model
                applications="$apptotal2"
                version_sistema_operativo=$version_sistema_operativo
                } | ConvertTo-Json -Compress
                #$apptotal2
                $item = $item.Replace("\r\n","")
              write-host  $item
