#Requires -Version 5.1
<#
.SYNOPSIS
  Regenerates WSecret MSIX, window and tray icons from src/WSecret/Assets/WSecret.png.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Assets = Join-Path $RepoRoot 'src\WSecret\Assets'
$Source = Join-Path $Assets 'WSecret.png'
$bitmap = [System.Drawing.Bitmap]::FromFile($Source)

try {
    $minX = $bitmap.Width
    $minY = $bitmap.Height
    $maxX = -1
    $maxY = -1
    for ($y = 0; $y -lt $bitmap.Height; $y++) {
        for ($x = 0; $x -lt $bitmap.Width; $x++) {
            if ($bitmap.GetPixel($x, $y).A -gt 8) {
                if ($x -lt $minX) { $minX = $x }
                if ($x -gt $maxX) { $maxX = $x }
                if ($y -lt $minY) { $minY = $y }
                if ($y -gt $maxY) { $maxY = $y }
            }
        }
    }
    if ($maxX -lt 0) { throw 'The source image has no visible pixels.' }
    $contentWidth = $maxX - $minX + 1
    $contentHeight = $maxY - $minY + 1

    function Render-Png([int]$Width, [int]$Height) {
        $canvas = New-Object System.Drawing.Bitmap($Width, $Height)
        try {
            $graphics = [System.Drawing.Graphics]::FromImage($canvas)
            try {
                $graphics.Clear([System.Drawing.Color]::Transparent)
                $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
                $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
                $scale = [Math]::Min(($Width * 0.84) / $contentWidth, ($Height * 0.84) / $contentHeight)
                $drawWidth = [Math]::Max(1, [int][Math]::Round($contentWidth * $scale))
                $drawHeight = [Math]::Max(1, [int][Math]::Round($contentHeight * $scale))
                $x = [int](($Width - $drawWidth) / 2)
                $y = [int](($Height - $drawHeight) / 2)
                $dest = New-Object System.Drawing.Rectangle($x, $y, $drawWidth, $drawHeight)
                $src = New-Object System.Drawing.Rectangle($minX, $minY, $contentWidth, $contentHeight)
                $graphics.DrawImage($bitmap, $dest, $src, [System.Drawing.GraphicsUnit]::Pixel)
            } finally {
                $graphics.Dispose()
            }
            $stream = New-Object System.IO.MemoryStream
            try {
                $canvas.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
                return ,$stream.ToArray()
            } finally {
                $stream.Dispose()
            }
        } finally {
            $canvas.Dispose()
        }
    }

    function Write-ScaledFile([string]$Name, [int]$Width, [int]$Height) {
        $bytes = Render-Png $Width $Height
        [System.IO.File]::WriteAllBytes((Join-Path $Assets $Name), $bytes)
    }

    Write-ScaledFile 'AppIcon.png' 256 256
    Write-ScaledFile 'StoreLogo.png' 50 50
    Write-ScaledFile 'Square44x44Logo.png' 44 44
    Write-ScaledFile 'SmallTile.png' 71 71
    Write-ScaledFile 'Square150x150Logo.png' 150 150
    Write-ScaledFile 'Square310x310Logo.png' 310 310
    Write-ScaledFile 'Wide310x150Logo.png' 310 150
    Write-ScaledFile 'SplashScreen.png' 620 300

    $sizes = @(16, 24, 32, 48, 64, 128, 256)
    $images = @()
    foreach ($size in $sizes) {
        $images += @{ Size = $size; Bytes = (Render-Png $size $size) }
    }
    $iconPath = Join-Path $Assets 'WSecret.ico'
    $writer = New-Object System.IO.BinaryWriter([System.IO.File]::Create($iconPath))
    try {
        $writer.Write([uint16]0)
        $writer.Write([uint16]1)
        $writer.Write([uint16]$images.Count)
        $offset = 6 + (16 * $images.Count)
        foreach ($image in $images) {
            $dimension = if ($image.Size -eq 256) { 0 } else { $image.Size }
            $writer.Write([byte]$dimension)
            $writer.Write([byte]$dimension)
            $writer.Write([byte]0)
            $writer.Write([byte]0)
            $writer.Write([uint16]1)
            $writer.Write([uint16]32)
            $writer.Write([uint32]$image.Bytes.Length)
            $writer.Write([uint32]$offset)
            $offset += $image.Bytes.Length
        }
        foreach ($image in $images) {
            $writer.Write([byte[]]$image.Bytes)
        }
    } finally {
        $writer.Dispose()
    }
} finally {
    $bitmap.Dispose()
}

Write-Host "Generated MSIX tiles and WSecret.ico in $Assets"
