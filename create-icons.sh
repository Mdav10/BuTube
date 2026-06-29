#!/bin/bash

# Create icons directory
mkdir -p public/icons

# Create SVG icon for each size
for size in 72 96 128 144 152 192 384 512; do
  cat > public/icons/icon-${size}x${size}.svg << SVG
<?xml version="1.0" encoding="UTF-8"?>
<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#ff6b6b;stop-opacity:1" />
      <stop offset="50%" style="stop-color:#ee5a24;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#c0392b;stop-opacity:1" />
    </linearGradient>
  </defs>
  
  <rect width="${size}" height="${size}" rx="$((size * 22 / 100))" ry="$((size * 22 / 100))" fill="url(#grad)"/>
  
  <g transform="translate($((size / 2)), $((size / 2 - size * 5 / 100)))">
    <polygon points="$(( -size * 30 / 100)),$(( -size * 45 / 100)) $((size * 45 / 100)),0 $(( -size * 30 / 100)),$((size * 45 / 100))" fill="white"/>
  </g>
  
  <text x="$((size / 2))" y="$((size * 88 / 100))" text-anchor="middle" fill="white" font-family="Arial, sans-serif" font-weight="bold" font-size="$((size * 18 / 100))">
    Bu
  </text>
</svg>
SVG
  echo "✅ Created icon-${size}x${size}.svg"
done

echo "✅ All BuTube app icons created as SVG!"
