# Kubernetes local

Manifiestos para correr el sistema en un cluster local como Docker Desktop,
minikube o kind.

## Imagenes locales

Construye las imagenes desde la raiz del proyecto:

```bash
docker build -t secure-auth-api:local .
docker build -t secure-auth-risk-service:local ./python-risk-service
```

## Secreto

Copia `secret.example.yaml` a `secret.yaml` y cambia `JWT_SECRET`.

```bash
copy k8s\secret.example.yaml k8s\secret.yaml
```

## Deploy

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/risk-service.yaml
kubectl apply -f k8s/auth-api.yaml
```

## Probar en localhost

```bash
kubectl -n secure-auth port-forward svc/auth-api 3000:3000
```

Luego abre:

```text
http://localhost:3000
```
