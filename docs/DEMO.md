# Demo para video corto

Duracion sugerida: 1 a 2 minutos.

## Guion

1. Abre `http://localhost:3000`.
2. Explica que el proyecto simula un flujo real de autenticacion segura.
3. Registra un usuario nuevo con password de al menos 12 caracteres.
4. Usa el token demo para verificar el email.
5. Inicia sesion y muestra el dashboard.
6. Presiona "Actualizar" para demostrar refresh token rotativo.
7. Muestra auditoria reciente y metricas de seguridad.
8. Abre el codigo y senala:
   - `src/auth.js`: Argon2, JWT, refresh tokens y TOTP.
   - `src/routes/authRoutes.js`: flujos de autenticacion.
   - `python-risk-service/main.py`: scoring de riesgo.
   - `k8s/`: manifiestos Kubernetes.

## Frase recomendada

> Este proyecto demuestra controles defensivos comunes en autenticacion:
> hashing con Argon2, JWT de corta duracion, refresh tokens rotativos, MFA,
> auditoria, rate limiting y scoring de riesgo separado en un microservicio.

## Capturas sugeridas

- `docs/screenshots/login-dashboard.png`
- Registro exitoso con token demo visible.
- Dashboard despues de iniciar sesion.
- Auditoria despues de login y refresh.
