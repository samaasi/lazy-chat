# Install lazy-chat on Windows:
#
#   irm https://raw.githubusercontent.com/samaasi/lazy-chat/master/scripts/install.ps1 | iex
#
# Downloads the release for this machine, checks it against the release's
# SHA-256 checksums and, when it can, the checksums' signature, then installs
# lazy-chat.exe and adds it to your user PATH. Nothing is installed if a check
# fails. No administrator rights are needed.
#
# Options (environment variables):
#   LAZYCHAT_VERSION      version to install, e.g. v1.2.3 (default: the latest)
#   LAZYCHAT_INSTALL_DIR  where to put it (default: %LOCALAPPDATA%\Programs\lazy-chat)
#   LAZYCHAT_REPO         owner/name on GitHub (default: samaasi/lazy-chat)
#   LAZYCHAT_BASE_URL     release download root (default: https://github.com/<repo>/releases)
#   LAZYCHAT_KEY_URL      where to fetch the release public key
#   LAZYCHAT_ALLOW_UNSIGNED=1  install even though the signature cannot be checked
#   LAZYCHAT_NO_PATH=1    do not modify PATH

& {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    function Fail($msg) { throw "install: $msg" }
    function Env($name, $default) {
        $v = [Environment]::GetEnvironmentVariable($name)
        if ([string]::IsNullOrEmpty($v)) { return $default }
        return $v
    }

    # An ASN.1 DER ECDSA signature (what cosign writes) as the fixed-width r||s that .NET expects.
    function ConvertFrom-DerSignature([byte[]]$der) {
        function Read-Len([byte[]]$b, [ref]$i) {
            $n = $b[$i.Value]; $i.Value++
            if ($n -lt 0x80) { return [int]$n }
            $count = $n -band 0x7f; $v = 0
            for ($k = 0; $k -lt $count; $k++) { $v = ($v -shl 8) -bor $b[$i.Value]; $i.Value++ }
            return $v
        }
        $i = 0
        if ($der.Length -lt 8 -or $der[$i] -ne 0x30) { Fail 'the release signature is malformed' }
        $i++; [void](Read-Len $der ([ref]$i))
        $parts = @()
        for ($n = 0; $n -lt 2; $n++) {
            if ($i -ge $der.Length -or $der[$i] -ne 0x02) { Fail 'the release signature is malformed' }
            $i++
            $len = Read-Len $der ([ref]$i)
            if ($len -le 0 -or $i + $len -gt $der.Length) { Fail 'the release signature is malformed' }
            $v = $der[$i..($i + $len - 1)]; $i += $len
            while ($v.Length -gt 1 -and $v[0] -eq 0) { $v = $v[1..($v.Length - 1)] }
            if ($v.Length -gt 32) { Fail 'the release signature is malformed' }
            $padded = New-Object byte[] 32
            [Array]::Copy($v, 0, $padded, 32 - $v.Length, $v.Length)
            $parts += , $padded
        }
        return [byte[]]($parts[0] + $parts[1])
    }

    $repo = Env 'LAZYCHAT_REPO' 'samaasi/lazy-chat'
    $base = (Env 'LAZYCHAT_BASE_URL' "https://github.com/$repo/releases").TrimEnd('/')

    # ---- Which build? ----------------------------------------------------------
    $cpu = $env:PROCESSOR_ARCHITEW6432
    if (-not $cpu) { $cpu = $env:PROCESSOR_ARCHITECTURE }
    switch ($cpu) {
        'AMD64' { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        default { Fail "unsupported CPU '$cpu'" }
    }

    # ---- Which version? --------------------------------------------------------
    $tag = Env 'LAZYCHAT_VERSION' ''
    if (-not $tag) {
        # /releases/latest redirects to /releases/tag/<tag>.
        $req = [Net.HttpWebRequest]::Create("$base/latest")
        $req.AllowAutoRedirect = $false
        $req.UserAgent = 'lazy-chat-installer'
        try { $resp = $req.GetResponse() } catch [Net.WebException] { $resp = $_.Exception.Response }
        if (-not $resp -or -not $resp.Headers['Location']) { Fail 'could not look up the latest release' }
        $tag = ($resp.Headers['Location'] -split '/')[-1]
        $resp.Close()
    }
    if ($tag -notmatch '^v\d+\.\d+\.\d+') { Fail "unexpected version '$tag'" }
    $version = $tag.Substring(1)
    $archive = "lazy-chat_${version}_windows_${arch}.zip"
    $url = "$base/download/$tag"

    $dir = Env 'LAZYCHAT_INSTALL_DIR' (Join-Path $env:LOCALAPPDATA 'Programs\lazy-chat')
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("lazychat-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null

    try {
        Write-Host "Installing lazy-chat $tag (windows/$arch) to $dir"
        $wc = New-Object Net.WebClient
        $wc.Headers['User-Agent'] = 'lazy-chat-installer'
        $wc.DownloadFile("$url/$archive", (Join-Path $tmp $archive))
        $wc.DownloadFile("$url/checksums.txt", (Join-Path $tmp 'checksums.txt'))

        # ---- Verify --------------------------------------------------------------
        $signed = $false
        try {
            $wc.DownloadFile("$url/checksums.txt.sig", (Join-Path $tmp 'checksums.txt.sig'))
            $keyUrl = Env 'LAZYCHAT_KEY_URL' "https://raw.githubusercontent.com/$repo/$tag/internal/update/release.pub"
            $pem = $wc.DownloadString($keyUrl)
            if ($pem -match 'BEGIN PUBLIC KEY') {
                $der = [Convert]::FromBase64String((($pem -split "`n") | Where-Object { $_ -notmatch '-----' }) -join '')
                $sigDer = [Convert]::FromBase64String(([IO.File]::ReadAllText((Join-Path $tmp 'checksums.txt.sig'))).Trim())
                $sums = [IO.File]::ReadAllBytes((Join-Path $tmp 'checksums.txt'))
                # Windows PowerShell 5.1 (.NET Framework) cannot import a PEM/DER key or a DER
                # signature directly, so read the P-256 point and the (r, s) pair by hand.
                if ($der.Length -lt 65 -or $der[$der.Length - 65] -ne 4) { Fail 'the release public key is not a P-256 key' }
                $q = New-Object Security.Cryptography.ECPoint
                $q.X = $der[($der.Length - 64)..($der.Length - 33)]
                $q.Y = $der[($der.Length - 32)..($der.Length - 1)]
                $params = New-Object Security.Cryptography.ECParameters
                $params.Curve = [Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')
                $params.Q = $q
                $ecdsa = [Security.Cryptography.ECDsa]::Create($params)
                $ok = $ecdsa.VerifyData($sums, (ConvertFrom-DerSignature $sigDer), [Security.Cryptography.HashAlgorithmName]::SHA256)
                if (-not $ok) { Fail 'the release signature does not match: refusing to install' }
                $signed = $true
            }
        } catch {
            if ("$_" -like 'install:*') { throw }
        }
        if ($signed) {
            Write-Host 'Signature verified.'
        } elseif ((Env 'LAZYCHAT_ALLOW_UNSIGNED' '') -eq '1') {
            Write-Host 'Warning: could not verify the release signature (continuing because LAZYCHAT_ALLOW_UNSIGNED=1).'
        } else {
            Write-Host 'Note: the release signature could not be checked here; relying on the SHA-256 checksum only.'
        }

        $want = $null
        foreach ($line in [IO.File]::ReadAllLines((Join-Path $tmp 'checksums.txt'))) {
            $f = $line -split '\s+'
            if ($f.Count -eq 2 -and ($f[1] -eq $archive -or $f[1] -eq "*$archive")) { $want = $f[0]; break }
        }
        if (-not $want) { Fail "no checksum listed for $archive" }
        # .NET directly: Get-FileHash is missing from PowerShell 3 and fails to load when PSModulePath is unusual.
        $sha = [Security.Cryptography.SHA256]::Create()
        $got = ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes((Join-Path $tmp $archive)))) -replace '-', '')
        if ($want -ne $got) { Fail "checksum mismatch for $archive (expected $want, got $got): refusing to install" }
        Write-Host 'Checksum verified.'

        # ---- Install -------------------------------------------------------------
        $x = Join-Path $tmp 'x'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $tmp $archive), $x)
        $exe = Get-ChildItem -Path $x -Recurse -Filter 'lazy-chat.exe' | Select-Object -First 1
        if (-not $exe -or $exe.Length -eq 0) { Fail 'lazy-chat.exe is not in the archive' }

        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $dest = Join-Path $dir 'lazy-chat.exe'
        # A running copy cannot be overwritten but can be renamed out of the way.
        if (Test-Path $dest) {
            $old = "$dest.old"
            Remove-Item -Force -ErrorAction SilentlyContinue $old
            Move-Item -Force $dest $old
        }
        Copy-Item -Force $exe.FullName $dest
        Remove-Item -Force -ErrorAction SilentlyContinue "$dest.old"

        Write-Host "Installed: $dest"
        if ((Env 'LAZYCHAT_NO_PATH' '') -ne '1') {
            $user = [Environment]::GetEnvironmentVariable('Path', 'User')
            $parts = @(($user -split ';') | Where-Object { $_ })
            if ($parts -notcontains $dir) {
                [Environment]::SetEnvironmentVariable('Path', (($parts + $dir) -join ';'), 'User')
                $env:Path = "$env:Path;$dir"
                Write-Host "Added $dir to your PATH (open a new terminal for it to take effect elsewhere)."
            }
        }
        Write-Host "Run 'lazy-chat --help' to get started. Update later with 'lazy-chat update'."
    } finally {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tmp
    }
}
