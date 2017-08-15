param (
  [Parameter(mandatory=$true)]
  [string]$appName,
  [Parameter(mandatory=$true)]
  [string]$buildVersion
)
$path = Split-Path -Parent $MyInvocation.MyCommand.Definition
$assemblyFile = (Join-Path $path "$appName\Properties\AssemblyInfo.cs")

Write-Host "Reading '$assemblyFile'"

$content = [IO.File]::ReadAllText($assemblyFile)

$regex = new-object System.Text.RegularExpressions.Regex ('(AssemblyVersion(Attribute)?\s*\(\s*\")(.*)(\"\s*\))',
         [System.Text.RegularExpressions.RegexOptions]::MultiLine)

$version = $null
$match = $regex.Match($content)
if($match.Success) {
    $version = $match.groups[3].value
}

Write-Host "Updating current AssemblyVersion '$version' to '$buildVersion'"

# update assembly info
$content = $regex.Replace($content, '${1}' + $buildVersion + '${4}')
[IO.File]::WriteAllText($assemblyFile, $content)
