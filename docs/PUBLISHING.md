# Checklist para publicar en GitHub

Antes de subir el proyecto:

- Confirma que `.env` no se sube al repositorio.
- Mantén `.env.example` como referencia.
- Revisa que `data/` no se suba.
- Ejecuta `npm test`.
- Toma capturas actualizadas en `docs/screenshots/`.
- Agrega una descripcion corta del proyecto en el repo.

## Comandos sugeridos

```bash
npm test
git init
git add .
git commit -m "Add secure authentication portfolio project"
```

Despues crea el repositorio en GitHub y sigue los comandos que GitHub indique
para agregar el remoto y hacer push.
