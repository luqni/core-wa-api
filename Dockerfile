# Gunakan image Node.js versi LTS
FROM node:18

# Tentukan direktori kerja dalam container
WORKDIR /app

# Salin package.json dan package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Salin seluruh project ke dalam container
COPY . .

# Tentukan port (opsional, hanya untuk dokumentasi)
EXPOSE 3000

# Perintah untuk menjalankan server
CMD ["node", "app.js"]
