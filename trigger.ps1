param (
  [Parameter(mandatory=$true)]
  [string]$project
)

$apiToken = $env:API_TOKEN

$headers = @{
  "Authorization" = "Bearer $apiToken"
  "Content-type" = "application/json"
}

$body = @{
    accountName = "hemantksingh"
    projectSlug = $project
    branch = "master"
}

$apiUrl = "https://ci.appveyor.com/api"
Invoke-RestMethod -Method Post -Uri "$apiUrl/builds" -Body (ConvertTo-Json $body) -Header $headers
