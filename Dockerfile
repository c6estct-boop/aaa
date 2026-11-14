FROM php:8.2-apache

# Apache mod_rewrite özelliğini aç (API routing / .htaccess kullanıyorsan şart)
RUN a2enmod rewrite

# Repodaki tüm dosyaları sunucunun ana dizinine kopyala
COPY . /var/www/html/

# Render'ın atadığı dinamik PORT'u Apache'ye tanıt
RUN sed -i 's/80/${PORT}/g' /etc/apache2/sites-available/000-default.conf /etc/apache2/ports.conf

# Dosya izinlerini ayarla
RUN chown -R www-data:www-data /var/www/html
