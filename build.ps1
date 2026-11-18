param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release'
)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    dotnet restore Assinador.Windows.slnx --locked-mode
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao restaurar as dependências.' }
    dotnet test Assinador.Windows.slnx --no-restore --configuration $Configuration --logger 'trx;LogFileName=windows-tests.trx' --results-directory artifacts/test-results
    if ($LASTEXITCODE -ne 0) { throw 'Os testes falharam.' }
    $publishPath = Join-Path $PSScriptRoot 'artifacts/publish/win-x64'
    dotnet publish src/Assinador.Windows/Assinador.Windows.csproj --configuration $Configuration --runtime win-x64 --self-contained true -p:RestoreLockedMode=true --output $publishPath
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao publicar o aplicativo.' }
    $version = ([xml](Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Directory.Build.props'))).Project.PropertyGroup.Version
    $archivePath = Join-Path $PSScriptRoot ('artifacts/assinador-windows-' + $version + '-win-x64.zip')
    Compress-Archive -Path (Join-Path $publishPath '*') -DestinationPath $archivePath -Force
    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath ($archivePath + '.sha256') -Value ($hash + '  ' + [IO.Path]::GetFileName($archivePath)) -Encoding utf8
    Write-Output ('Pacote portátil: ' + $archivePath)
} finally { Pop-Location }
