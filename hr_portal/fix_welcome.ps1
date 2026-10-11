$src = 'C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_portal\index.html'
$dst = 'C:\Program Files\AI-Prowler\hr_portal\index.html'
$h = [IO.File]::ReadAllText($src, [Text.Encoding]::UTF8)
$s = $h.IndexOf('<!-- WELCOME PAGE -->')
$e = $h.IndexOf('<!-- PORTFOLIO PAGE -->')
if ($e -lt 0) { $e = $h.IndexOf('<!-- HOME') }
$blank = '<!-- WELCOME PAGE -->' + "`n      <div class=""page"" id=""page-welcome""></div>`n`n      "
$out = $h.Substring(0,$s) + $blank + $h.Substring($e)
[IO.File]::WriteAllText($src, $out, [Text.Encoding]::UTF8)
Copy-Item $src $dst -Force
Write-Host 'DONE'

