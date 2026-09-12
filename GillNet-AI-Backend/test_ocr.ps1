Add-Type -AssemblyName System.Drawing
[Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Storage.Streams.InMemoryRandomAccessStream, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null

$bmp = New-Object System.Drawing.Bitmap 400, 100
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.Clear([System.Drawing.Color]::White)
$font = New-Object System.Drawing.Font "Arial", 16
$brush = [System.Drawing.Brushes]::Black
$g.DrawString("Sign-in attempt was blocked", $font, $brush, 10, 30)
$g.Dispose()

$ms = New-Object System.IO.MemoryStream
$bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
$bytes = $ms.ToArray()
$bmp.Dispose()
$ms.Dispose()

$stream = New-Object Windows.Storage.Streams.InMemoryRandomAccessStream
$writer = New-Object Windows.Storage.Streams.DataWriter $stream
$writer.WriteBytes($bytes)

$op1 = $writer.StoreAsync()
while ($op1.Status.ToString() -eq 'Started') { Start-Sleep -Milliseconds 10 }
$null = $op1.GetResults()

$op2 = $writer.FlushAsync()
while ($op2.Status.ToString() -eq 'Started') { Start-Sleep -Milliseconds 10 }
$null = $op2.GetResults()

$stream.Seek(0)

$op3 = [Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)
while ($op3.Status.ToString() -eq 'Started') { Start-Sleep -Milliseconds 10 }
$decoder = $op3.GetResults()

$op4 = $decoder.GetSoftwareBitmapAsync()
while ($op4.Status.ToString() -eq 'Started') { Start-Sleep -Milliseconds 10 }
$softwareBitmap = $op4.GetResults()

$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
$op5 = $engine.RecognizeAsync($softwareBitmap)
while ($op5.Status.ToString() -eq 'Started') { Start-Sleep -Milliseconds 10 }
$result = $op5.GetResults()

Write-Output "OCR SUCCESS: $($result.Text)"
