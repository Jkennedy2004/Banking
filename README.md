# 🏦 Aplicación Bancaria

Una aplicación bancaria segura y lista para producción construida con Node.js, que incluye medidas de seguridad avanzadas, pruebas automatizadas y un pipeline CI/CD.

## 🚀 Características

- **Autenticación Segura**: Autenticación basada en JWT con contraseñas cifradas con bcrypt  
- **Gestión de Cuentas**: Consultas de saldo e historial de transacciones  
- **Transferencias de Fondos**: Transferencias seguras entre cuentas  
- **Seguridad Prioritaria**: Varias capas de protección  
- **Limitación de Peticiones**: Contra ataques de fuerza bruta  
- **Validación de Entradas**: Sanitización y validación exhaustiva  
- **Registro de Auditoría**: Registro completo de transacciones e intentos de inicio de sesión  

## 🔐 Características de Seguridad

- **Cumplimiento OWASP**: Siguiendo las mejores prácticas del Top 10 de OWASP  
- **Helmet.js**: Protección mediante encabezados HTTP  
- **Prevención de Inyección SQL**: Consultas parametrizadas y validación de entradas  
- **Protección contra XSS**: Sanitización de entradas y cabeceras CSP  
- **Limitación de Peticiones**: Control de tasa y bloqueo de intentos  
- **Seguridad de Sesión**: Gestión segura de tokens JWT  
- **Contraseñas Seguras**: Requisitos fuertes y hash seguro  
- **Protección CORS**: Políticas configurables  
- **Encabezados de Seguridad**: Configuración completa de headers HTTP  

## ⚡ Inicio Rápido

### Requisitos Previos

- Node.js 18.x o superior  
- MySQL 8.0 o superior  
- Docker (opcional)

### Instalación

1. **Clonar el repositorio**
```bash
git clone https://github.com/company/banking-app.git
cd banking-app
```

2. **Instalar dependencias**
```bash
npm install
```

3. **Configurar variables de entorno**
```bash
cp .env.example .env
# Editar .env con tu configuración
```

4. **Configurar base de datos**
```bash
mysql -u root -p -e "CREATE DATABASE banking_db;"
mysql -u root -p -e "CREATE USER 'banking_user'@'localhost' IDENTIFIED BY 'secure_password';"
mysql -u root -p -e "GRANT ALL PRIVILEGES ON banking_db.* TO 'banking_user'@'localhost';"
npm run init-db
```

5. **Iniciar la aplicación**
```bash
# Modo desarrollo
npm run dev

# Modo producción
npm start
```

## 🐳 Despliegue con Docker

### Construir y correr con Docker

```bash
npm run build

docker run -d   --name banking-app   -p 3000:3000   -e DB_HOST=tu-host   -e DB_USER=banking_user   -e DB_PASSWORD=secure_password   -e DB_NAME=banking_db   -e JWT_SECRET=tu-clave-jwt   banking-app:latest
```

### Docker Compose

```bash
docker-compose up -d
docker-compose logs -f banking-app
docker-compose down
```

## 🧪 Pruebas

### Ejecutar todas las pruebas
```bash
npm test
```

### Pruebas específicas
```bash
npm run test:unit
npm run test:security
npm run test -- --coverage
```

### Pruebas de Seguridad
```bash
npm run lint
npm run security:snyk
npm audit
npm run sonar
```

## 📡 Documentación API

### Autenticación

#### POST `/api/auth/login`
Solicita autenticación y recibe JWT.

#### POST `/api/auth/register`
Registra un nuevo usuario.

### Cuenta

Todos los endpoints requieren token JWT:

```
Authorization: Bearer <JWT_TOKEN>
```

#### GET `/api/account/balance`
Consulta saldo actual.

#### GET `/api/account/transactions`
Consulta historial de transacciones.

#### POST `/api/account/transfer`
Realiza una transferencia.

## 🏗️ Arquitectura

### Estructura del Proyecto
```
banking-app/
├── src/
├── tests/
├── docker/
├── security/
└── .github/workflows/
```

### Esquema de Base de Datos

#### Tabla `users`
Campos: id, email, password_hash, nombres, estado, rol, timestamps.

#### Tabla `accounts`
Campos: id, user_id, número de cuenta, tipo, saldo, estado, timestamps.

## 🔧 Configuración

### Variables de Entorno

Archivo `.env` de ejemplo:

```env
NODE_ENV=production
PORT=3000
DB_HOST=localhost
DB_USER=banking_user
DB_PASSWORD=secure_password
DB_NAME=banking_db
JWT_SECRET=tu-clave-jwt
ALLOWED_ORIGINS=https://tu-frontend.com
```

## 🔄 CI/CD Pipeline

### Workflows

- Análisis de código (ESLint, SonarQube)  
- Escaneo de seguridad (Snyk, OWASP)  
- Pruebas automáticas  
- Build Docker  
- Despliegue automático  

### Seguridad

- SAST, DAST  
- Análisis diario  
- Escaneo de contenedores  
- Checks de infraestructura  

## 📊 Monitoreo y Logs

- Endpoint `/health`  
- Logs con Winston  
- Métricas de rendimiento  
- Detección de actividad sospechosa  

### Ejemplo de Log
```json
{
  "timestamp": "...",
  "level": "info",
  "message": "Inicio de sesión exitoso",
  ...
}
```

## 🛡️ Mejores Prácticas de Seguridad

1. **Autenticación y Roles**
2. **Protección de Datos**
3. **Seguridad de Red**
4. **Seguridad de Aplicación**

### Lista de Verificación

- [ ] Actualización de dependencias  
- [ ] Pentesting  
- [ ] Plan de incidentes  
- [ ] Capacitación  
- [ ] Backups  
- [ ] Auditorías de cumplimiento  

## 🤝 Contribuir

1. **Fork del repositorio**  
2. **Crear rama**
```bash
git checkout -b feature/nueva-funcionalidad
```

3. **Hacer cambios y pruebas**
```bash
npm test
npm run lint
npm run security:snyk
```

4. **Commit y Push**
```bash
git commit -m "feat: nueva funcionalidad"
git push origin feature/nueva-funcionalidad
```

5. **Crear Pull Request**

## 📋 Despliegue

### Lista de verificación para Producción

- [ ] Variables configuradas  
- [ ] Migraciones aplicadas  
- [ ] Certificados SSL  
- [ ] Monitoreo configurado  
- [ ] Backups y pruebas de recuperación  
- [ ] Escaneo de seguridad completo  
- [ ] Pruebas de rendimiento  
- [ ] Documentación actualizada  

### Escalabilidad

- **Horizontal**: Balanceadores de carga  
- **Base de Datos**: Réplicas de lectura  
- **Cache**: Redis  
- **CDN**: Para contenido estático  
- **Monitoreo**: Full-stack  

## 📞 Soporte

- **Documentación**: Este README  
- **Issues**: GitHub  
- **Seguridad**: security@banking-app.com  
- **General**: team@banking-app.com  

## 📄 Licencia

Este proyecto está bajo la licencia MIT - ver el archivo [LICENSE](LICENSE).

## 🙏 Agradecimientos

- OWASP  
- Node.js Security WG  
- Estándares de la industria bancaria  
- Comunidad Open Source

---

⚠️ **Aviso de Seguridad**: Esta aplicación maneja datos financieros sensibles. Sigue siempre las mejores prácticas de seguridad, mantén actualizadas las dependencias y realiza auditorías regularmente.
