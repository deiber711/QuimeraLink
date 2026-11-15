# Subir la v1.0 a un repositorio privado

Git registra el historial en tu equipo. GitHub guarda una copia remota de ese
repositorio. Un commit es un punto guardado del historial; un push lo envía a
GitHub. La etiqueta `v1.0` permite identificar este punto en el futuro.

## 1. Abre PowerShell en la carpeta preparada

```powershell
Set-Location -LiteralPath 'C:\Users\sampc\OneDrive\Documentos\ChatGPT\Detector de phishing'
Get-ChildItem -Force
git --version
```

Aquí está la copia preparada. El archivo de la carpeta original permanece intacto.

## 2. Crea el repositorio vacío en GitHub

Inicia sesión en https://github.com y abre https://github.com/new.

- Selecciona tu cuenta como propietario.
- Nombre: `detector-de-phishing`.
- Descripción sugerida: `Proyecto educativo: capturas web como base para un detector de phishing.`
- Selecciona **Private**.
- No agregues README, `.gitignore` ni licencia desde GitHub: los archivos
  iniciales se enviarán desde el equipo.
- Pulsa **Create repository** y copia la URL HTTPS que termina en `.git`.

## 3. Inicia el historial y configura el autor

Si no has iniciado Git en esta carpeta, ejecuta:

```powershell
git init -b main
```

Antes del primer commit, reemplaza los textos de ejemplo:

```powershell
git config --local user.name "TU NOMBRE O USUARIO"
git config --local user.email "TU CORREO NOREPLY DE GITHUB"
```

Copia tu dirección `noreply` exacta desde https://github.com/settings/emails;
no escribas literalmente el texto del ejemplo. Permite que el commit no
incluya tu correo personal. `--local` aplica la configuración solo aquí.
El nombre del autor no es una contraseña ni inicia sesión en GitHub.

## 4. Revisa y guarda la versión inicial

```powershell
git add main.py README.md requirements.txt .gitignore .gitattributes CHANGELOG.md GUIA_GITHUB.md
git diff --cached --stat
git diff --cached
git status
```

`add` prepara los archivos para el commit. Revisa el contenido antes de seguir:
deben aparecer solo esos siete archivos, sin credenciales ni capturas.
Si la vista del diff ocupa una pantalla completa, pulsa `q` para salir.

```powershell
git commit -m "Prepara v1.0: capturas web con Playwright"
git tag -a v1.0 -m "Version 1.0: capturas de pantalla"
```

`commit` guarda la versión local. `tag` le asigna el nombre `v1.0`.
`.gitignore` evita agregar archivos coincidentes nuevos; no elimina del
historial archivos que ya se hubieran guardado en commits anteriores.

## 5. Conecta con GitHub y sube el proyecto

Reemplaza `TU_USUARIO` por el propietario que elegiste, o pega la URL HTTPS
exacta que copiaste de GitHub:

```powershell
git remote add origin https://github.com/TU_USUARIO/detector-de-phishing.git
git remote -v
git push -u origin main
git push origin v1.0
```

`origin` es el nombre de la conexión con GitHub. El primer push envía la rama
`main`; `-u` recuerda su destino para próximos pushes. El segundo envía la etiqueta.
Si Git Credential Manager abre el navegador, completa allí el inicio de sesión.
No incluyas contraseñas ni tokens en la URL o en los archivos del proyecto.

Si aparece `remote origin already exists`, revisa `git remote -v` antes de
cambiar nada. Si el destino ya es correcto, continúa con el push. Si aparece
`Repository not found`, comprueba la URL y que hayas iniciado sesión con una
cuenta que tenga acceso. Si el push es rechazado porque el remoto tiene commits,
detente para revisar ambos historiales; no uses `--force`.

## 6. Verifica el resultado

```powershell
git status
git log -1 --oneline
git ls-remote --heads --tags origin
```

En GitHub, actualiza la página y comprueba la indicación **Private**, los siete
archivos y la etiqueta `v1.0` en la sección de etiquetas. La salida de
`ls-remote` debe incluir `refs/heads/main` y `refs/tags/v1.0`.

## 7. Guarda tus siguientes avances

```powershell
git status
git diff
git add NOMBRE_DEL_ARCHIVO_MODIFICADO
git diff --cached
git commit -m "Describe el avance que terminaste"
git push
```

Sustituye el nombre de archivo por uno real. Haz commits pequeños con un
propósito claro. La etiqueta `v1.0` conservará la referencia a esta primera
versión mientras seguimos trabajando hacia la v1.1.

## Referencias oficiales

- https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github?platform=windows
- https://docs.github.com/en/account-and-profile/how-tos/email-preferences/setting-your-commit-email-address
