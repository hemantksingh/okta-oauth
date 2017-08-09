param (
  [Parameter(mandatory=$true)]
  [string]$project
)

$headers = @{
  "Authorization" = "Bearer $env.API_TOKEN"
  "Content-type" = "application/json"
}

$body = @{
    accountName = "hemantksingh"
    projectSlug = $project
    branch = "master"
}

$apiUrl = "https://ci.appveyor.com/api"
Invoke-RestMethod -Method Post -Uri "$apiUrl/builds" -Body (ConvertTo-Json $body) -Header $headers
