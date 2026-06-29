const fs = require('fs');
const path = require('path');
const { createCanvas } = require('canvas');

const sizes = [72, 96, 128, 144, 152, 192, 384, 512];

if (!fs.existsSync('public/icons')) {
  fs.mkdirSync('public/icons', { recursive: true });
}

sizes.forEach(size => {
  const canvas = createCanvas(size, size);
  const ctx = canvas.getContext('2d');
  
  // Background - YouTube-style red gradient
  const gradient = ctx.createRadialGradient(
    size * 0.3, size * 0.3, size * 0.1,
    size * 0.5, size * 0.5, size * 0.7
  );
  gradient.addColorStop(0, '#ff6b6b');
  gradient.addColorStop(0.5, '#ee5a24');
  gradient.addColorStop(1, '#c0392b');
  ctx.fillStyle = gradient;
  
  // Rounded rectangle
  const radius = size * 0.22;
  ctx.beginPath();
  ctx.moveTo(radius, 0);
  ctx.lineTo(size - radius, 0);
  ctx.quadraticCurveTo(size, 0, size, radius);
  ctx.lineTo(size, size - radius);
  ctx.quadraticCurveTo(size, size, size - radius, size);
  ctx.lineTo(radius, size);
  ctx.quadraticCurveTo(0, size, 0, size - radius);
  ctx.lineTo(0, radius);
  ctx.quadraticCurveTo(0, 0, radius, 0);
  ctx.closePath();
  ctx.fill();
  
  // White border glow
  ctx.shadowColor = 'rgba(255,255,255,0.1)';
  ctx.shadowBlur = size * 0.05;
  
  // Play triangle (YouTube style)
  const triSize = size * 0.3;
  const centerX = size / 2;
  const centerY = size / 2;
  
  ctx.fillStyle = '#ffffff';
  ctx.shadowColor = 'rgba(0,0,0,0.3)';
  ctx.shadowBlur = size * 0.05;
  ctx.shadowOffsetX = 0;
  ctx.shadowOffsetY = size * 0.02;
  
  ctx.beginPath();
  ctx.moveTo(centerX - triSize * 0.45, centerY - triSize * 0.6);
  ctx.lineTo(centerX + triSize * 0.65, centerY);
  ctx.lineTo(centerX - triSize * 0.45, centerY + triSize * 0.6);
  ctx.closePath();
  ctx.fill();
  
  // "Bu" text below play button
  ctx.shadowColor = 'rgba(0,0,0,0.5)';
  ctx.shadowBlur = size * 0.03;
  ctx.shadowOffsetY = size * 0.02;
  
  ctx.fillStyle = '#ffffff';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'bottom';
  const fontSize = size * 0.18;
  ctx.font = `bold ${fontSize}px Arial, "Inter", sans-serif`;
  ctx.fillText('Bu', centerX, size - fontSize * 0.4);
  
  // Small shine effect
  ctx.shadowColor = 'rgba(255,255,255,0.15)';
  ctx.shadowBlur = size * 0.1;
  ctx.fillStyle = 'rgba(255,255,255,0.08)';
  ctx.beginPath();
  ctx.ellipse(size * 0.2, size * 0.2, size * 0.25, size * 0.15, -0.5, 0, Math.PI * 2);
  ctx.fill();
  
  // Save as PNG
  const buffer = canvas.toBuffer('image/png');
  fs.writeFileSync(path.join('public/icons', `icon-${size}x${size}.png`), buffer);
  console.log(`✅ Created icon-${size}x${size}.png`);
});

console.log('✅ All BuTube app icons created!');
console.log('📱 Your app will now install as a native app on Android!');
