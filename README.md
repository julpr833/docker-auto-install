# Docker Installer (PowerShell)

Script simple para instalar y configurar Docker en Windows automáticamente.

## Uso

```bat
RUN.bat
```
o de manera remota:
```powershell
$url = "https://raw.githubusercontent.com/julpr833/docker-auto-install/main/install_docker.ps1"
$output = "$env:TEMP\install_docker.ps1"

Invoke-WebRequest $url -OutFile $output
powershell -NoProfile -ExecutionPolicy Bypass -File $output
```
