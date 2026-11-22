# privscan

Auditor de **SUID, SGID y capabilities** para Linux. Con un solo comando:

1. Enumera todos los binarios con SUID/SGID y capabilities.
2. Marca los que **no deberían** tener esos privilegios (🔴 crítico / 🟡 revisar).
3. Te deja elegir, binario a binario, cómo corregirlo.
4. Guarda un script de restauración para **deshacer** cualquier cambio.

Un único fichero Bash, sin dependencias externas (opcional: `libcap2-bin` para capabilities).
Probado en Debian/Ubuntu/Parrot/Kali; funciona también con rpm y pacman.

## Instalación

```bash
git clone https://github.com/0NetFox/privscan.git
cd privscan
sudo install -m 0755 privscan.sh /usr/local/bin/privscan
```

## Uso

```bash
sudo privscan            # escaneo + menú interactivo para corregir
sudo privscan --list     # solo informe (exit 1 si hay críticos; apto para cron/CI)
sudo privscan --all      # incluye también los binarios normales
sudo privscan -x /mnt/datos   # excluye rutas del escaneo
sudo privscan --undo     # deshace los últimos cambios
```

### Menú interactivo

```
 [CRÍTICO] /tmp/find (1/3)
     tipo: SUID | permisos: 4755 | propietario: root:root
       • SUID en un binario que permite obtener shell root (GTFOBins)
       • ubicación inusual donde escriben usuarios normales
   Acciones:
     [1] Quitar SUID                 (chmod u-s)
     [i] Ignorar (es legítimo: añadir a allowlist)
     [d] Ver detalles   [s] Saltar (Enter)   [q] Salir
```

Opciones: quitar SUID, SGID, capabilities o todo; ignorar (allowlist); ver detalles
(paquete propietario, hash, enlace a GTFOBins); saltar; salir. Cada cambio pide confirmación.

## Cómo clasifica

| Nivel | Criterio |
|---|---|
| 🔴 Crítico | Binario de [GTFOBins](https://gtfobins.github.io/) (bash, find, vim, python…) con SUID/SGID/caps · ubicación inusual (`/tmp`, `/home`, `/dev/shm`…) · escribible por grupo/otros · capabilities equivalentes a root (`cap_setuid`, `cap_sys_admin`, `cap_dac_override`…) · no pertenece a ningún paquete |
| 🟡 Revisar | No figura en la lista de binarios habituales · SUID con propietario distinto de root · script con SUID · capabilities no habituales |
| ✔ Normal | Binarios típicos (`sudo`, `su`, `passwd`, `mount`, `ping`…) en rutas del sistema |

Las listas están al principio de `privscan.sh` (`BASELINE`, `GTFO`, `CAP_BASELINE`); edítalas a tu gusto.

## Deshacer

Antes del primer cambio se crea `/var/backups/privscan/restore-FECHA.sh` con los permisos y
capabilities originales. `sudo privscan --undo` muestra su contenido y lo ejecuta tras confirmar.

## Allowlist

Los binarios que marques con `[i]` se guardan en `/etc/privscan/allowlist.txt` (una ruta por línea)
y dejan de aparecer como hallazgos.

## Avisos

- **Quitar SUID a binarios del sistema puede romper funciones** (`sudo`, `su`, `mount`, `passwd`…).
  Por eso los habituales no se ofrecen para corregir. Revisa cada caso.
- Un hallazgo no implica compromiso: puede ser software de terceros legítimo. Usa `[d]` para investigar.
- Si encuentras un binario crítico que **no instalaste tú**, trátalo como posible intrusión.
- Se excluyen `/proc`, `/sys`, `/dev`, `/run`, `/snap` y contenedores (`/var/lib/docker`, etc.).
- Rutas con saltos de línea no están soportadas.

## Probarlo de forma segura

```bash
sudo cp /bin/find /tmp/find && sudo chmod u+s /tmp/find
sudo privscan --list      # debe aparecer como CRÍTICO
sudo privscan             # elige [1] para quitar SUID
sudo privscan --undo      # restaura
sudo rm /tmp/find
```

## Contribuir

PRs bienvenidas: ampliar listas, soporte para más gestores de paquetes, salida JSON. Pasa `shellcheck privscan.sh`.

## Licencia

MIT
