# Cert-Manager Webhook for ISPConfig

## Install

### Config & Pre-Flight
Have a look at `testdata/ispconfig-solver/`, copy and modify them to match your environment, then run the test
Don't change the name of the secret `ispconfig-secret` in the manifest.
```
TEST_ZONE_NAME=example.com. make test
```

If the test was successfull, you can already apply `testdata/ispconfig-solver/ispconfig-secret.yaml` to your cluster
```
k -n cert-manager apply -f testdata/ispconfig-solver/ispconfig-secret.yaml
```

### Helm
```
helm install ispconfig-webhook deploy/cert-manager-webhook-ispconfig -n cert-manager
```

### Legacy (Helm generated template)
```
make rendered-manifest.yaml
kubectl apply -n cert-manager -f _out/rendered-manifest.yaml
```

### Testing
See `examples/` to add a clusterissuer and a first test certificate to your cluster.

