# GitHub üzerinden Windows EXE hazırlama

1. GitHub'da yeni bir **public veya private** depo açın.
2. Bu ZIP paketini çıkartın. İçindeki `YAS_BinaryLab_X_V1_7` klasörünün **içeriğini** (CMakeLists.txt, src, tests, .github) depo köküne yükleyin. `.github` klasörünü mutlaka koruyun.
3. GitHub'da **Actions** sekmesine girin.
4. **Build YAS BinaryLab X Windows EXE** iş akışını açın ve **Run workflow** seçin.
5. Tüm adımlar başarılıysa çalıştırma sayfasının **Artifacts** bölümündeki `YAS-BinaryLab-X-Windows-x64` dosyasını indirin.
6. Dış ZIP'i açın, ardından içindeki `YAS_BinaryLab_X_Windows_x64.zip` paketini çıkartın. `YASBinaryLabX.exe` ve yanındaki Qt DLL dosyalarını birlikte tutun.

**Notlar:** GitHub Actions üzerinde build otomatik çalışır ama kod hatalıysa EXE oluşmaz. İlgili kırmızı adımın günlük kayıtlarını paylaşın. Testler de başarısızsa paket yayımlanmaz. Derleme için Qt MSVC 2022 64-bit seçilir. Capstone kurulmazsa CMake tasarımına göre disassembler özelliği derlemede pasif kalır. İlk denemede GitHub üzerinde başarılı build alınana kadar paket doğrulanmış sayılmaz. `windows-2022` GitHub-hosted runner kotası ve GitHub hesabınızın Actions izinlerine tabidir.
