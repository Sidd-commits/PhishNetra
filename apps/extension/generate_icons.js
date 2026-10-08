const fs = require('fs');
const path = require('path');

// 1x1 transparent/blue PNG buffer fallback
const base64Png = 'iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAMAAAD04JH5AAAAD1BMVEUAAAD/AAA0NDQ8PDz///8t8l7HAAAAAXRSTlMAQObYZgAAAFBJREFUeNrtwTEBAAAAwqD1T20ND6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4Dc14AABw7F+PAAAAABJRU5ErkJggg==';
const iconBuffer = Buffer.from(base64Png, 'base64');

const iconDir = path.join(__dirname, 'icons');
if (!fs.existsSync(iconDir)) {
  fs.mkdirSync(iconDir, { recursive: true });
}

[16, 32, 48, 128].forEach((size) => {
  fs.writeFileSync(path.join(iconDir, `icon${size}.png`), iconBuffer);
});

console.log('Icons generated successfully.');
