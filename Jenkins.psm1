<#
.EXTERNALHELP Jenkins-help.xml
#>
#Requires -version 5.0

$moduleRoot = Split-Path `
    -Path $MyInvocation.MyCommand.Path `
    -Parent

#region LocalizedData
$culture = 'en-US'
if (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath $PSUICulture))
{
    $culture = $PSUICulture
}

Import-LocalizedData `
    -BindingVariable LocalizedData `
    -Filename 'Jenkins.strings.psd1' `
    -BaseDirectory $moduleRoot `
    -UICulture $culture
#endregion

#region Functions
function Disable-JenkinsJob
{
    [CmdLetBinding(SupportsShouldProcess = $true)]
    [OutputType([System.String])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder,

        [parameter(
            Position = 5,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name
    )

    $null = $PSBoundParameters.Add('Type', 'Command')

    $Command = Resolve-JenkinsCommandUri -Folder $Folder -JobName $Name -Command 'disable'

    $optionalParams = @{}
    if( $Credential )
    {
        $optionalParams['Credential'] = $Credential
    }

    if( $Crumb )
    {
        $optionalParams['Crumb'] = $Crumb
    }

    $displayName = $Name
    if( $Folder )
    {
        $displayName = '{0}/{1}' -f $Folder,$Name
    }

    if ($PSCmdlet.ShouldProcess( $Uri, $($LocalizedData.DisableJobMessage -f $displayName)))
    {
        $null = Invoke-JenkinsCommand -Uri $Uri -Type 'Command' -Command $Command -Method post @optionalParams
    }
}


function Enable-JenkinsJob
{
    [CmdLetBinding(SupportsShouldProcess = $true)]
    [OutputType([System.String])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder,

        [parameter(
            Position = 5,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name
    )

    $null = $PSBoundParameters.Add('Type', 'Command')

    $Command = Resolve-JenkinsCommandUri -Folder $Folder -JobName $Name -Command 'enable'

    $optionalParams = @{}
    if( $Credential )
    {
        $optionalParams['Credential'] = $Credential
    }

    if( $Crumb )
    {
        $optionalParams['Crumb'] = $Crumb
    }

    $displayName = $Name
    if( $Folder )
    {
        $displayName = '{0}/{1}' -f $Folder,$Name
    }

    if ($PSCmdlet.ShouldProcess( $Uri, $($LocalizedData.EnableJobMessage -f $displayName)))
    {
        $null = Invoke-JenkinsCommand -Uri $Uri -Type 'Command' -Command $Command -Method post @optionalParams
    }
}

function Get-JenkinsCrumb
{
    [CmdLetBinding()]
    [OutputType([System.String])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential
    )

    if ($PSBoundParameters.ContainsKey('Credential'))
    {
        # Jenkins Credentials were passed so create the Authorization Header
        $Username = $Credential.Username

        # Decrypt the secure string password
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
        $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Username + ':' + $Password)
        $Base64Bytes = [System.Convert]::ToBase64String($Bytes)

        $Headers += @{ "Authorization" = "Basic $Base64Bytes" }
    } # if

    $null = $PSBoundParameters.remove('Uri')
    $null = $PSBoundParameters.remove('Credential')
    $FullUri = '{0}/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,":",//crumb)' -f $Uri

    try
    {
        Write-Verbose -Message $($LocalizedData.GetCrumbMessage -f
            $FullUri)

        Set-JenkinsTLSSupport

        $Result = Invoke-WebRequest `
            -Uri $FullUri `
            -Headers $Headers `
            -ErrorAction Stop
    }
    catch
    {
        # Todo: Improve error handling.
        Throw $_
    } # catch

    $Regex = '^Jenkins-Crumb:([A-Z0-9]*)'
    $Matches = @([regex]::matches($Result.Content, $Regex, 'IgnoreCase'))

    if (-not $Matches.Groups)
    {
        # Attempt to match the alternate Jenkins Crumb format
        $Regex = '^.crumb:([A-Z0-9]*)'
        $Matches = @([regex]::matches($Result.Content, $Regex, 'IgnoreCase'))
        if (-not $Matches.Groups)
        {
            $ExceptionParameters = @{
                errorId       = 'CrumbResponseFormatError'
                errorCategory = 'InvalidArgument'
                errorMessage  = $($LocalizedData.CrumbResponseFormatError -f `
                        $Result.Content)
            }
            New-JenkinsException @ExceptionParameters
        } # if
    } # if

    $Crumb = $Matches.Groups[1].Value

    return $Crumb
} # Get-JenkinsCrumb

function Get-JenkinsFolderList
{
    [CmdLetBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder
    )

    $null = $PSBoundParameters.Add( 'Type', 'jobs')
    $null = $PSBoundParameters.Add( 'Attribute', @( 'name', 'url', 'color' ) )
    $null = $PSBoundParameters.Add( 'IncludeClass', 'com.cloudbees.hudson.plugins.folder.Folder')
    return Get-JenkinsObject `
        @PSBoundParameters
} # Get-JenkinsFolderList

function Get-JenkinsJob
{
    [CmdLetBinding()]
    [OutputType([System.String])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder,

        [parameter(
            Position = 5,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name
    )

    $null = $PSBoundParameters.Add('Type', 'Command')

    $Command = Resolve-JenkinsCommandUri -Folder $Folder -JobName $Name -Command 'config.xml'

    $null = $PSBoundParameters.Remove('Name')
    $null = $PSBoundParameters.Remove('Folder')
    $null = $PSBoundParameters.Add('Command', $Command)
    $configXml = (Invoke-JenkinsCommand @PSBoundParameters).Content
    return $configXml -replace '^<\?xml\ version=(''|")1\.1(''|")', '<?xml version=''1.0'''
} # Get-JenkinsJob

function Get-JenkinsJobList
{
    [CmdLetBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder,

        [parameter(
            Position = 5,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $IncludeClass,

        [parameter(
            Position = 6,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $ExcludeClass
    )

    $null = $PSBoundParameters.Add( 'Type', 'jobs')
    $null = $PSBoundParameters.Add( 'Attribute', @( 'name', 'buildable', 'url', 'color' ) )

    # If a class was not explicitly excluded or included then excluded then
    # set the function to excluded folders.
    if (-not $PSBoundParameters.ContainsKey('ExcludeClass') `
            -and -not $PSBoundParameters.ContainsKey('IncludeClass'))
    {
        $PSBoundParameters.Add('ExcludeClass', @('com.cloudbees.hudson.plugins.folder.Folder'))
    } # if

    return Get-JenkinsObject `
        @PSBoundParameters
} # Get-JenkinsJobList

function Get-JenkinsObject
{
    [CmdLetBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Type,

        [parameter(
            Position = 5,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Attribute,

        [parameter(
            Position = 6,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder,

        [parameter(
            Position = 7,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $IncludeClass,

        [parameter(
            Position = 8,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $ExcludeClass
    )

    $null = $PSBoundParameters.Remove('Type')
    $null = $PSBoundParameters.Remove('Attribute')
    $null = $PSBoundParameters.Remove('IncludeClass')
    $null = $PSBoundParameters.Remove('ExcludeClass')
    $null = $PSBoundParameters.Remove('Folder')

    # To support the Folders plugin we have to create a tree
    # request that is limited to the depth of the folder we're looking for.
    $TreeRequestSplat = @{
        Type      = $Type
        Attribute = $Attribute
    }

    if ($Folder)
    {
        $FolderItems = ($Folder -split '\\') -split '/'
        $TreeRequestSplat = @{
            Depth     = ($FolderItems.Count + 1)
            Attribute = $Attribute
        }
    } # if
    $Command = Get-JenkinsTreeRequest @TreeRequestSplat
    $PSBoundParameters.Add('Command', $Command)

    $Result = Invoke-JenkinsCommand @PSBoundParameters
    $Objects = $Result.$Type

    if ($Folder)
    {
        # A folder was specified, so find it
        foreach ($FolderItem in $FolderItems)
        {

            foreach ($Object in $Objects)
            {

                if ($FolderItem -eq $Object.Name)
                {
                    $Objects = $Object.$Type
                } # if
            } # foreach
        } # foreach
    } # if

    if ($IncludeClass)
    {
        $Objects = $Objects | Where-Object -Property _class -In $IncludeClass
    } # if

    if ($ExcludeClass)
    {
        $Objects = $Objects | Where-Object -Property _class -NotIn $ExcludeClass
    } # if

    return $Objects
} # Get-JenkinsObject

function Get-JenkinsPluginsList
{
    [CmdLetBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [System.String]
        $Api = 'json',

        [parameter(
            Position = 5,
            Mandatory = $false)]
        [System.String]
        $Depth = '1'
    )

    # Add/Remove PSBoundParameters so they can be splatted
    $null = $PSBoundParameters.Add('Type', 'pluginmanager')
    $null = $PSBoundParameters.Add('Command', "depth=$Depth")
    $null = $PSBoundParameters.Remove('Depth')

    # Invoke the Command to Get the Plugin List
    $result = Invoke-JenkinsCommand @PSBoundParameters
    $objects = ConvertFrom-Json -InputObject $result.Content

    # Returns the list of plugins, selecting just the name and version.
    return ($objects.plugins | Select-Object shortName, version)
} # Get-JenkinsPluginsList

<#
    .SYNOPSIS
        Assembles the tree request component for a Jenkins request.

    .DESCRIPTION
        This cmdlet will assemble the ?tree= component of a Jenkins Rest API call
        to limit the return of specific types and levels of information.

    .PARAMETER Depth
        The maximum number of levels of the tree to return.

    .PARAMETER Type
        The category of elements to return. Can be: jobs, views.

    .PARAMETER Attribute
        An array of attributes to return for each level of the tree. The attributes
        available will depend on the type specified.

    .EXAMPLE
        $request = Get-JenkinsTreeRequest -Depth 4 -Type 'Jobs' -Attribute 'Name'
        Invoke-JenkinsCommand -Uri 'https://jenkins.contoso.com/' -Command $request
        This will return all Jobs within 4 levels of the tree. Only the name
        attribute will be returned.

    .OUTPUTS
        String containing tree request.
#>
function Get-JenkinsTreeRequest
{
    [CmdLetBinding()]
    [OutputType([System.String])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $false)]
        [System.Int32]
        $Depth = 1,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Type = 'jobs',

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Attribute = @( 'name', 'buildable', 'url', 'color' )
    )

    $allAttributes = $Attribute -join ','
    $treeRequest = "?tree=$Type[$allAttributes"

    for ($level = 1; $level -lt $Depth; $level++)
    {
        $treeRequest += ",$Type[$allAttributes"
    } # foreach

    $treeRequest += ']' * $Depth

    return $treeRequest
} # Get-JenkinsTreeRequest

function Get-JenkinsViewList
{
    [CmdLetBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String] $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()] $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String] $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String[]] $IncludeClass,

        [parameter(
            Position = 5,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String[]] $ExcludeClass
    )

    $null = $PSBoundParameters.Add( 'Type', 'views')
    $null = $PSBoundParameters.Add( 'Attribute', @( 'name', 'url' ) )
    return Get-JenkinsObject `
        @PSBoundParameters
} # Get-JenkinsViewList

function Initialize-JenkinsUpdateCache
{
    [CmdLetBinding(SupportsShouldProcess = $true)]
    [OutputType([System.IO.FileInfo])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $false)]
        [System.String]
        $Uri = 'http://updates.jenkins-ci.org/update-center.json',

        [parameter(
            Position = 2,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( { Test-Path -Path $_ })]
        [System.String]
        $Path,

        [parameter(
            Position = 3,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CacheUri,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Include,

        [parameter(
            Position = 5,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Exclude,

        [Switch]
        $UpdateCore,

        [Switch]
        $Force
    )

    if ($CacheUri.EndsWith('/'))
    {
        $CacheUri = $CacheUri.Substring(0, $CacheUri.Length - 1)
    } # if

    # Download the Remote Update Center JSON
    Write-Verbose -Message $($LocalizedData.DownloadingRemoteUpdateListMessage -f
        $Uri)

    Set-JenkinsTLSSupport

    $remotePluginJSON = Invoke-WebRequest `
        -Uri $Uri `
        -UseBasicParsing
    $result = $remotePluginJSON.Content -match 'updateCenter.post\(\r?\n(.*)\r?\n\);'

    if (-not $result)
    {
        $ExceptionParameters = @{
            errorId       = 'UpdateListBadFormatError'
            errorCategory = 'InvalidArgument'
            errorMessage  = $($LocalizedData.UpdateListBadFormatError -f `
                    'remote', $Uri)
        }
        New-JenkinsException @ExceptionParameters
    }
    $remoteJSON = ConvertFrom-Json -InputObject $Matches[1]

    # Generate an array of the Remote plugins and versions
    Write-Verbose -Message $($LocalizedData.ProcessingRemoteUpdateListMessage -f
        $Uri)

    $remotePlugins = [System.Collections.ArrayList] @()
    $remotePluginList = ($remoteJSON.Plugins |
            Get-Member -MemberType NoteProperty).Name
    foreach ($plugin in $remotePluginList)
    {
        if ($Include)
        {
            $addIt = $false
            # Includes only the entries that match the $Include array
            foreach ($item in $Include)
            {
                if ($plugin -like $item)
                { $addIt = $true
                }
            }
        }
        elseif ($Exclude)
        {
            # Excludes the entries that match the $Exclude array
            $addIt = $true
            foreach ($item in $Exclude)
            {
                if ($plugin -notlike $item)
                { $addIt = $false
                }
            }
        } # if
        if ($addIt)
        {
            $null = $remotePlugins.Add( $remoteJSON.Plugins.$plugin )
        }
    } # foreach

    $localUpdateListPath = Join-Path -Path $Path -ChildPath 'update-center.json'
    if (Test-Path -Path $localUpdateListPath)
    {
        $localPluginJSON = Get-Content -Path $localUpdateListPath -Raw
        $result = $localPluginJSON -match 'updateCenter.post\(\r?\n(.*)\r?\n\);'

        if (-not $result)
        {
            $exceptionParameters = @{
                errorId       = 'UpdateListBadFormatError'
                errorCategory = 'InvalidArgument'
                errorMessage  = $($LocalizedData.UpdateListBadFormatError -f `
                        'local', $localUpdateListPath)
            }
            New-JenkinsException @exceptionParameters
        }
        $localJSON = ConvertFrom-Json -InputObject $Matches[1]

        # Generate an array of the Remote plugins and versions
        Write-Verbose -Message $($LocalizedData.ProcessingLocalUpdateListMessage -f
            $localUpdateListPath)

        $localPlugins = [System.Collections.ArrayList] @()
        $localPluginList = ($LocalJSON.Plugins |
                Get-Member -MemberType NoteProperty).Name

        foreach ($plugin in $localPluginList)
        {
            if ($Include)
            {
                $addIt = $false
                # Includes only the entries that match the $Include array
                foreach ($item in $Include)
                {
                    if ($plugin -like $item)
                    { $addIt = $true
                    }
                }
            }
            elseif ($Exclude)
            {
                # Excludes the entries that match the $Exclude array
                $addIt = $true
                foreach ($item in $Exclude)
                {
                    if ($plugin -notlike $item)
                    { $addIt = $false
                    }
                }
            } # if
            if ($addIt)
            {
                $null = $localPlugins.Add( $localJSON.Plugins.$plugin )
            }
        } # foreach
    }
    else
    {
        $localPlugins = [System.Collections.ArrayList] @()
    } # if

    <#
        Now perform the comparison between the plugins that exist and the ones
        that need to be downloaded and download any missing ones.
        Step down the list of remote plugins in reverse so that we can remove
        elements from the array.
    #>
    $cacheUpdated = $false
    for ($pluginNumber = $RemotePlugins.Count - 1; $pluginNumber -ge 0; $pluginNumber--)
    {
        $remotePlugin = $RemotePlugins[$pluginNumber]
        Write-Verbose -Message $($LocalizedData.ProcessingPluginMessage -f
            $remotePlugin.name, $remotePlugin.version )

        $pluginFilename = Split-Path -Path $remotePlugin.url -Leaf

        # Find out if the plugin already exists.
        $needsUpdate = $true
        $foundPlugin = $null
        foreach ($localPlugin in $LocalPlugins)
        {
            if ($localPlugin.name -eq $remotePlugin.name)
            {
                $foundPlugin = $localPlugin
                if ($localPlugin.version -eq $remotePlugin.version)
                {
                    # TODO: Add hash check to validate cached file
                    $needsUpdate = $false
                    break
                } # if
            } # if
        } # foreach

        if ($foundPlugin)
        {
            Write-Verbose -Message $($LocalizedData.ExistingPluginFoundMessage -f
                $foundPlugin.name, $foundPlugin.version)
        }

        if ($needsUpdate)
        {
            $downloadOK = $false

            if ($Force -or $PSCmdlet.ShouldProcess(`
                        $remotePlugin.name, `
                    $($LocalizedData.UpdateJenkinsPluginMessage -f $remotePlugin.name, $remotePlugin.verion)))
            {
                # A new version of the plugin needs to be downloaded
                $PluginFilePath = Join-Path -Path $Path -ChildPath $pluginFilename

                if (Test-Path -Path $PluginFilePath)
                {
                    # The plugin file already exists so remove it
                    Write-Verbose -Message $($LocalizedData.RemovingPluginFileMessage -f
                        $PluginFilePath)

                    $null = Remove-Item -Path $PluginFilePath -Force
                } # if

                Write-Verbose -Message $($LocalizedData.DownloadingPluginMessage -f
                    $remotePlugin.name, $remotePlugin.url, $PluginFilePath)

                # Download the plugin
                try
                {
                    Invoke-WebRequest `
                        -Uri $remotePlugin.url `
                        -UseBasicParsing `
                        -OutFile $PluginFilePath `
                        -ErrorAction Stop
                    $downloadOK = $true
                }
                catch
                {
                    Write-Error -Exception $_
                } # try
                if ($downloadOk)
                {
                    $cacheUpdated = $true
                } # if
            } # if

            if ($downloadOk)
            {
                if ($foundPlugin)
                {
                    # The plugin already exists so remove the entry before adding a new one
                    $null = $localPlugins.Remove($foundPlugin)
                } # if

                # Add the plugin to the local plugins list
                $remotePlugin.url = "$CacheUri/$pluginFilename"
                $null = $localPlugins.Add( $remotePlugin )

                # Report that the file was downloaded
                Get-ChildItem -Path $pluginFilePath
            } # if
        } # if
    } # foreach

    if ($cacheUpdated)
    {
        # Generate new Local Plugin JSON object
        $newPlugins = New-Object PSCustomObject
        foreach ($plugin in $localPlugins | Sort-Object -Property name)
        {
            $null = Add-Member `
                -InputObject $newPlugins `
                -Type NoteProperty `
                -Name $plugin.name `
                -Value $plugin
        } # foreach
        $remoteJSON.plugins = $newPlugins
    } # if

    if ($UpdateCore)
    {
        # Need to see if the Jenkins Core needs to be updated
        $coreFilename = Split-Path -Path $remoteJSON.Core.url -Leaf

        if (($localJSON.Core.version -ne $remoteJSON.Core.version) -or `
            ($localJSON.Core.url -ne "$CacheUri/$coreFilename"))
        {
            $downloadOK = $false

            if ($Force -or $PSCmdlet.ShouldProcess(`
                        $remoteJSON.Core.version, `
                    $($LocalizedData.UpdateJenkinsCoreMessage -f $remoteJSON.Core.version)))
            {
                # A new version of the plugin needs to be downloaded
                $coreFilePath = Join-Path -Path $Path -ChildPath $coreFilename

                if (Test-Path -Path $coreFilePath)
                {
                    # The plugin file already exists so remove it
                    Write-Verbose -Message $($LocalizedData.RemovingJenkinsCoreFileMessage -f
                        $coreFilePath)

                    $null = Remove-Item -Path $coreFilePath -Force
                } # if

                Write-Verbose -Message $($LocalizedData.DownloadingJenkinsCoreMessage -f
                    $remoteJSON.Core.url, $coreFilePath)

                try
                {
                    Invoke-WebRequest `
                        -Uri $remoteJSON.Core.url `
                        -UseBasicParsing `
                        -OutFile $coreFilePath `
                        -ErrorAction Stop
                    $downloadOK = $true
                }
                catch
                {
                    Write-Error -Exception $_
                } # try
                if ($downloadOk)
                {
                    # Update the Cache List file
                    $remoteJSON.Core.Url = "$CacheUri/$coreFilename"
                    $cacheUpdated = $true

                    # Report that the file was downloaded
                    Get-ChildItem -Path $coreFilePath

                } # if
            } # if
        }
        else
        {
            Write-Verbose -Message $($LocalizedData.ExistingJenkinsCoreFoundMessage -f
                $remoteJSON.Core.version)
        } # if
    } # if

    if ($cacheUpdated)
    {
        # Convert the JSON object into JSON
        $newJSON = ConvertTo-Json -InputObject $remoteJSON -Compress

        # Create the new Local Plugin JSON file content
        $localPluginJSON = "updateCenter.post(`n$newJSON`n);"
        if ($Force -or $PSCmdlet.ShouldProcess(`
                    $localUpdateListPath, `
                $($LocalizedData.CreateJenkinsUpdateListMessage -f $localUpdateListPath)))
        {
            # Write out the new Local Update List file
            if (Test-Path -Path $localUpdateListPath)
            {
                $null = Remove-Item -Path $localUpdateListPath -Force
            } # if
            $null = Set-Content -Path $localUpdateListPath -Value $localPluginJSON -NoNewline
        } # if
    } # if
} # Initialize-JenkinsUpdateCache

function Invoke-JenkinsCommand
{
    [CmdLetBinding()]
    [OutputType([System.String])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateSet('rest', 'command', 'restcommand', 'pluginmanager')]
        [System.String]
        $Type = 'rest',

        [parameter(
            Position = 5,
            Mandatory = $false)]
        [System.String]
        $Api = 'json',

        [parameter(
            Position = 6,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Command,

        [parameter(
            Position = 7,
            Mandatory = $false)]
        [ValidateSet('default', 'delete', 'get', 'head', 'merge', 'options', 'patch', 'post', 'put', 'trace')]
        [System.String]
        $Method,

        [parameter(
            Position = 8,
            Mandatory = $false)]
        [System.Collections.Hashtable]
        $Headers = @{},

        [parameter(
            Position = 9,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ContentType,

        [parameter(
            Position = 10,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        $Body
    )

    if ($PSBoundParameters.ContainsKey('Credential') -and $Credential -ne [System.Management.Automation.PSCredential]::Empty)
    {
        # Jenkins Credentials were passed so create the Authorization Header
        $username = $Credential.Username

        # Decrypt the secure string password
        $passwordBstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($passwordBstr)

        $authorizationBytes = [System.Text.Encoding]::UTF8.GetBytes($username + ':' + $password)
        $authorizationBytesBase64 = [System.Convert]::ToBase64String($authorizationBytes)

        $Headers += @{ "Authorization" = "Basic $authorizationBytesBase64" }
    } # if

    if ($PSBoundParameters.ContainsKey('Crumb'))
    {
        Write-Verbose -Message $($LocalizedData.UsingCrumbMessage -f
            $Crumb)

        # Support both Jenkins and Cloudbees Jenkins Enterprise
        $Headers += @{ "Jenkins-Crumb" = $Crumb }
        $Headers += @{ ".crumb" = $Crumb }
    } # if

    $null = $PSBoundParameters.remove('Uri')
    $null = $PSBoundParameters.remove('Credential')
    $null = $PSBoundParameters.remove('Crumb')
    $null = $PSBoundParameters.remove('Type')
    $null = $PSBoundParameters.remove('Headers')

    switch ($Type)
    {
        'rest'
        {
            $fullUri = "$Uri/api/$Api"

            if ($PSBoundParameters.ContainsKey('Command'))
            {
                $fullUri = $fullUri + '/' + $Command
            } # if

            $null = $PSBoundParameters.remove('Command')
            $null = $PSBoundParameters.remove('Api')

            try
            {
                Write-Verbose -Message $($LocalizedData.InvokingRestApiCommandMessage -f
                    $fullUri)

                Set-JenkinsTLSSupport

                $result = Invoke-RestMethod `
                    -Uri $fullUri `
                    -Headers $Headers `
                    @PSBoundParameters `
                    -ErrorAction Stop
            }
            catch
            {
                # Todo: Improve error handling.
                Throw $_
            } # catch
        } # 'rest'

        'restcommand'
        {
            $fullUri = "$Uri/$Command"

            $null = $PSBoundParameters.remove('Command')
            $null = $PSBoundParameters.remove('Api')

            try
            {
                Write-Verbose -Message $($LocalizedData.InvokingRestApiCommandMessage -f
                    $fullUri)

                Set-JenkinsTLSSupport

                $result = Invoke-RestMethod `
                    -Uri $fullUri `
                    -Headers $Headers `
                    @PSBoundParameters `
                    -ErrorAction Stop
            }
            catch
            {
                # Todo: Improve error handling.
                Throw $_
            } # catch
        } # 'restcommand'

        'command'
        {
            $fullUri = $Uri

            if ($PSBoundParameters.ContainsKey('Command'))
            {
                $fullUri = $fullUri + '/' + $Command
            } # if

            $null = $PSBoundParameters.remove('Command')
            $null = $PSBoundParameters.remove('Api')

            Write-Verbose -Message $($LocalizedData.InvokingCommandMessage -f
                $fullUri)

            Set-JenkinsTLSSupport

            $result = Invoke-WebRequest `
                -UseBasicParsing `
                -Uri $fullUri `
                -Headers $Headers `
                -MaximumRedirection 0 `
                @PSBoundParameters `
                -ErrorAction SilentlyContinue `
                -ErrorVariable RequestErrors

            if ($RequestErrors.Count -eq 1 -and $result.StatusCode -eq 302 `
                    -and $RequestErrors[0].FullyQualifiedErrorId -like "MaximumRedirectExceeded,*")
            {
                Write-Verbose -Message $($LocalizedData.SuppressingRedirectMessage -f $result.Headers.Location)
            }
            elseif ($RequestErrors.Count -ge 1)
            {
                # Todo: Improve error handling.
                throw $RequestErrors[0].Exception
            }
        } # 'command'

        'pluginmanager'
        {
            $fullUri = $Uri

            if ($PSBoundParameters.ContainsKey('Command'))
            {
                $fullUri = "$fullUri/pluginManager/api/$api/?$Command"
            } # if (condition) {

            $null = $PSBoundParameters.remove('Command')
            $null = $PSBoundParameters.remove('Api')

            try
            {
                Write-Verbose -Message $($LocalizedData.InvokingCommandMessage -f
                    $fullUri)

                Set-JenkinsTLSSupport

                $result = Invoke-WebRequest `
                    -UseBasicParsing `
                    -Uri $fullUri `
                    -Headers $Headers `
                    @PSBoundParameters `
                    -ErrorAction Stop
            }
            catch
            {
                # Todo: Improve error handling.
                Throw $_
            } # catch
        } # 'pluginmanager'
    } # switch

    return $result
} # Invoke-JenkinsCommand

function Invoke-JenkinsJob
{
    [CmdLetBinding()]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder,

        [parameter(
            Position = 5,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [parameter(
            Position = 6,
            Mandatory = $false)]
        [Hashtable]
        $Parameters
    )

    $command = Resolve-JenkinsCommandUri -Folder $Folder -JobName $Name -Command 'build'

    $null = $PSBoundParameters.Remove('Name')
    $null = $PSBoundParameters.Remove('Folder')
    $null = $PSBoundParameters.Remove('Confirm')
    $null = $PSBoundParameters.Add('Command', $command)
    $null = $PSBoundParameters.Add('Method', 'post')
    $null = $PSBoundParameters.Add('Type', 'Command')

    $body = @{}

    if ($PSBoundParameters.ContainsKey('Parameters'))
    {
        $postValues = @()

        foreach ($key in $Parameters.Keys)
        {
            $postValues += @(
                @{
                    name = $key
                    value = $Parameters[$key]
                }
            )
        }

        $jsonBody = @{
            parameter = $postValues
        }

        $body = @{
            json = ConvertTo-Json -InputObject $jsonBody
        }

        $null = $PSBoundParameters.Remove('Parameters')
        $null = $PSBoundParameters.Add('Body', $body)
    }

    return Invoke-JenkinsCommand @PSBoundParameters
} # Invoke-JenkinsJob

function Invoke-JenkinsJobReload
{
    [CmdLetBinding()]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb
    )

    # Invoke-JenkinsCommand with the 'reload' rest command
    Invoke-JenkinsCommand `
        -Uri $uri `
        -Credential $Credential `
        -Crumb $Crumb `
        -Type 'restcommand' `
        -Command 'reload' `
        -Method 'post' `
        -Verbose
} # function Invoke-JenkinsJobReload

<#
    .SYNOPSIS
        Throws a custom exception.

    .DESCRIPTION
        This cmdlet throws a terminating or non-terminating exception.

    .PARAMETER errorId
        The Id of the exception.

    .PARAMETER errorCategory
        The category of the exception. It must be a valid [System.Management.Automation.ErrorCategory]
        value.

    .PARAMETER errorMessage
        The exception message.

    .PARAMETER terminate
        This switch will cause the exception to terminate the cmdlet.

    .EXAMPLE
        $ExceptionParameters = @{
            errorId = 'ConnectionFailure'
            errorCategory = 'ConnectionError'
            errorMessage = 'Could not connect'
        }
        New-JenkinsException @ExceptionParameters
        Throw a ConnectionError exception with the message 'Could not connect'.

    .OUTPUTS
        None
#>
function New-JenkinsException
{
    [CmdLetBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ErrorId,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorCategory]
        $ErrorCategory,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ErrorMessage,

        [Switch]
        $Terminate
    )

    $exception = New-Object -TypeName System.Exception `
        -ArgumentList $ErrorMessage
    $errorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord `
        -ArgumentList $exception, $ErrorId, $ErrorCategory, $null

    if ($true -or $())
    {
        if ($Terminate)
        {
            # This is a terminating exception.
            throw $errorRecord
        }
        else
        {
            # Note: Although this method is called ThrowTerminatingError, it doesn't terminate.
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
    } # if
} # function New-JenkinsException

function New-JenkinsFolder
{
    [CmdLetBinding(SupportsShouldProcess = $true)]
    [OutputType([System.String])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder,

        [parameter(
            Position = 5,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [parameter(
            Position = 6,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Description,

        [parameter(
            Position = 7,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $XML
    )

    $null = $PSBoundParameters.Add('Type', 'Command')
    if (-not ($PSBoundParameters.ContainsKey('XML')))
    {
        # Generate the XML we need to use to create the job
        $XML = @"
<?xml version='1.0' encoding='UTF-8'?>
<com.cloudbees.hudson.plugins.folder.Folder plugin="cloudbees-folder">
  <actions/>
  <description>$Description</description>
  <properties/>
</com.cloudbees.hudson.plugins.folder.Folder>
"@
    }
    $null = $PSBoundParameters.Remove('XML')

    $Command = Resolve-JenkinsCommandUri -Folder $Folder -Command "createItem?name=$Name"

    $null = $PSBoundParameters.Remove('Name')
    $null = $PSBoundParameters.Remove('Description')
    $null = $PSBoundParameters.Remove('Folder')
    $null = $PSBoundParameters.Remove('Confirm')
    $null = $PSBoundParameters.Add('Command', $Command)
    $null = $PSBoundParameters.Add('Method', 'post')
    $null = $PSBoundParameters.Add('ContentType', 'application/xml')
    $null = $PSBoundParameters.Add('Body', $XML)
    if ($PSCmdlet.ShouldProcess(`
                $URI, `
            $($LocalizedData.NewFolderMessage -f $Name)))
    {
        $null = Invoke-JenkinsCommand @PSBoundParameters
    } # if
} # New-JenkinsFolder

function New-JenkinsJob
{
    [CmdLetBinding(SupportsShouldProcess = $true)]
    [OutputType([System.String])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder,

        [parameter(
            Position = 5,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [parameter(
            Position = 6,
            Mandatory = $true,
            ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $XML
    )

    $null = $PSBoundParameters.Add('Type', 'Command')

    $Command = Resolve-JenkinsCommandUri -Folder $Folder -Command ("createItem?name={0}" -f [System.Uri]::EscapeDataString($Name))

    $null = $PSBoundParameters.Remove('Name')
    $null = $PSBoundParameters.Remove('Folder')
    $null = $PSBoundParameters.Remove('XML')
    $null = $PSBoundParameters.Remove('Confirm')
    $null = $PSBoundParameters.Add('Command', $Command)
    $null = $PSBoundParameters.Add('Method', 'post')
    $null = $PSBoundParameters.Add('ContentType', 'application/xml')
    $null = $PSBoundParameters.Add('Body', $XML)

    if ($PSCmdlet.ShouldProcess(`
                $URI, `
            $($LocalizedData.NewJobMessage -f $Name)))
    {
        $null = Invoke-JenkinsCommand @PSBoundParameters
    } # if
} # New-JenkinsJob

function Remove-JenkinsJob
{
    [CmdLetBinding(SupportsShouldProcess = $true,
        ConfirmImpact = "High")]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder,

        [parameter(
            Position = 5,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [Switch]
        $Force
    )

    $null = $PSBoundParameters.Add('Type', 'Command')

    $Command = Resolve-JenkinsCommandUri -Folder $Folder -JobName $Name -Command 'doDelete'

    $null = $PSBoundParameters.Remove('Name')
    $null = $PSBoundParameters.Remove('Folder')
    $null = $PSBoundParameters.Remove('Confirm')
    $null = $PSBoundParameters.Remove('Force')
    $null = $PSBoundParameters.Add('Command', $Command)
    $null = $PSBoundParameters.Add('Method', 'post')

    if ($Force -or $PSCmdlet.ShouldProcess(`
                $URI, `
            $($LocalizedData.RemoveJobMessage -f $Name)))
    {
        $null = Invoke-JenkinsCommand @PSBoundParameters
    } # if
} # Remove-JenkinsJob

function Rename-JenkinsJob
{
    [CmdLetBinding(SupportsShouldProcess = $true,
        ConfirmImpact = "High")]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [parameter(
            Position = 5,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $NewName,

        [parameter(
            Position = 6,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder,

        [Switch]
        $Force
    )

    $null = $PSBoundParameters.Add('Type', 'Command')

    $Command = Resolve-JenkinsCommandUri -Folder $Folder -JobName $Name -Command ("doRename?newName={0}" -f [System.Uri]::EscapeDataString($NewName))

    $null = $PSBoundParameters.Remove('Name')
    $null = $PSBoundParameters.Remove('NewName')
    $null = $PSBoundParameters.Remove('Confirm')
    $null = $PSBoundParameters.Remove('Force')
    $null = $PSBoundParameters.Remove('Folder')
    $null = $PSBoundParameters.Add('Command', $Command)
    $null = $PSBoundParameters.Add('Method', 'post')

    if ($Force -or $PSCmdlet.ShouldProcess( `
                $URI, `
            $($LocalizedData.RenameJobMessage -f $Name, $NewName)))
    {
        $null = Invoke-JenkinsCommand @PSBoundParameters
    } # if
} # Rename-JenkinsJob


function Resolve-JenkinsCommandUri
{
    [CmdLetBinding()]
    [OutputType([System.String])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $false)]
        [System.String]
        $Folder,

        [parameter(
            Position = 2)]
        [System.String]
        $JobName,

        [parameter(
            Position = 3,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Command
    )

    $segments = & {
                        if( $Folder )
                        {
                            ($Folder -split '\\') -split '/'
                        }

                        if( $JobName )
                        {
                            $JobName
                        }
                }
    $uri = ''
    if( $segments )
    {
        $uri = $segments -join '/job/'
        $uri = ('job/{0}/' -f $uri)
    }
    return '{0}{1}' -f $uri,$Command
}


function Set-JenkinsJob
{
    [CmdLetBinding(SupportsShouldProcess = $true)]
    [OutputType([System.String])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder,

        [parameter(
            Position = 5,
            Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        [parameter(
            Position = 6,
            Mandatory = $true,
            ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $XML
    )

    $null = $PSBoundParameters.Add('Type', 'Command')

    $Command = Resolve-JenkinsCommandUri -Folder $Folder -JobName $Name -Command 'config.xml'

    $null = $PSBoundParameters.Remove('Name')
    $null = $PSBoundParameters.Remove('Folder')
    $null = $PSBoundParameters.Remove('XML')
    $null = $PSBoundParameters.Remove('Confirm')
    $null = $PSBoundParameters.Add('Command', $Command)
    $null = $PSBoundParameters.Add('Method', 'post')
    $null = $PSBoundParameters.Add('ContentType', 'application/xml')
    $null = $PSBoundParameters.Add('Body', $XML)

    if ($PSCmdlet.ShouldProcess(`
                $URI, `
            $($LocalizedData.SetJobDefinitionMessage -f $Name)))
    {
        $null = Invoke-JenkinsCommand @PSBoundParameters
    } # if
} # Set-JenkinsJob

<#
    .SYNOPSIS
        Enables PowerShell to support TLS1.2 for communicating with
        newer versions of Jenkins.

    .DESCRIPTION
        This support cmdlet enables connecting to newer versions of
        Jenkins over HTTPS. Newer versions of Jenkins have deprecated
        support for SSL3/TLS, which are the default supported HTTPS
        protocols.

    .OUTPUTS
        None
#>
function Set-JenkinsTLSSupport
{
    [CmdLetBinding()]
    param
    (
    )

    if (-not ([Net.ServicePointManager]::SecurityProtocol).ToString().Contains([Net.SecurityProtocolType]::Tls12))
    {
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.ServicePointManager]::SecurityProtocol.toString() + ', ' + [Net.SecurityProtocolType]::Tls12
    }
} # function Set-JenkinsTLSSupport

function Test-JenkinsFolder
{
    [CmdLetBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder,

        [parameter(
            Position = 5,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name
    )

    $null = $PSBoundParameters.Add( 'Type', 'jobs')
    $null = $PSBoundParameters.Add( 'Attribute', @( 'name' ) )
    $null = $PSBoundParameters.Add( 'IncludeClass', 'com.cloudbees.hudson.plugins.folder.Folder')
    $null = $PSBoundParameters.Remove( 'Name' )
    return ((@(Get-JenkinsObject @PSBoundParameters | Where-Object -Property Name -eq $Name)).Count -gt 0)
} # Test-JenkinsFolder

function Test-JenkinsJob
{
    [CmdLetBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Folder,

        [parameter(
            Position = 5,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name
    )

    $null = $PSBoundParameters.Add( 'Type', 'jobs')
    $null = $PSBoundParameters.Add( 'Attribute', @( 'name' ) )
    $null = $PSBoundParameters.Remove( 'Name' )
    return ((@(Get-JenkinsObject @PSBoundParameters | Where-Object -Property Name -eq $Name)).Count -gt 0)
} # Test-JenkinsJob

function Test-JenkinsView
{
    [CmdLetBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(
            Position = 1,
            Mandatory = $true)]
        [System.String]
        $Uri,

        [parameter(
            Position = 2,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [parameter(
            Position = 3,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Crumb,

        [parameter(
            Position = 4,
            Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name
    )

    $null = $PSBoundParameters.Add( 'Type', 'views')
    $null = $PSBoundParameters.Add( 'Attribute', @( 'name' ) )
    $null = $PSBoundParameters.Remove( 'Name' )

    return ((@(Get-JenkinsObject @PSBoundParameters | Where-Object -Property Name -eq $Name)).Count -gt 0)
} # Test-JenkinsView


#endregion

