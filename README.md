# Assinador PDF para Windows

Aplicativo nativo em C#, WPF, .NET 10 e iText Community 9.6.0, sob GNU AGPL v3.
Prévia local do PDF, selo visível com posição escolhida pelo usuário e assinatura
com certificados pessoais disponíveis no Windows. Projeto independente, pronto
para seu próprio repositório.

## Executar

Windows 10 versão 2004 ou superior / Windows 11, arquitetura x64.
Extraia todo o pacote portátil e abra **Assinador.Windows.exe**. A versão publicada
inclui o runtime .NET: o computador de destino não precisa instalar o SDK ou .NET.
O aplicativo executa como usuário comum, sem solicitar privilégios administrativos.

1. Clique em **ABRIR PDF** e selecione o documento.
2. Navegue até a página, arraste o selo e ajuste seu tamanho. O zoom amplia a prévia;
   as setas do teclado também movem o selo quando ele está em foco.
3. Clique em **ASSINAR**. Escolha imediatamente a pasta e o nome da cópia, sugerido como
   `nome_assinado.pdf`. O original não pode ser sobrescrito. Outros arquivos existentes
   podem ser substituídos após confirmação. O mesmo nome em outra pasta é permitido.
4. Escolha um certificado no **diálogo padrão de certificados pessoais do Windows**.
   Ele abre novamente a cada assinatura; o aplicativo não guarda o último certificado
   como padrão. Os detalhes do certificado podem ser consultados no próprio diálogo.
5. Se necessário, informe o PIN no diálogo do próprio provedor do certificado.
   Após a verificação, a cópia é assinada, conferida criptograficamente e gravada.

As ações principais são somente **ABRIR PDF** e **ASSINAR**, lado a lado no topo.
O aplicativo não tem botões de certificado, salvar cópia ou ver. O Motivo e o Local
podem ser preenchidos em opções como metadados; o Motivo não aparece no selo.
Nenhum QR Code é incluído.

## Certificados e classificação do selo

São lidos os armazenamentos **Pessoal** do usuário atual e do computador local,
somente para leitura. São listados certificados de titular válidos, com chave privada,
uso permitido de assinatura e algoritmo RSA ou EC. Por padrão, a seleção exibe apenas
certificados cuja cadeia válida chega a uma das raízes ICP-Brasil exatas incluídas.
Essa filtragem não substitui a verificação completa de revogação após a seleção.
Um arquivo público CER sem chave privada não é suficiente. A instalação de PFX/P12
deve ser feita pelo próprio Windows.

As operações RSA/SHA-256 e ECDSA/SHA-256 usam as APIs criptográficas CAPI/CNG do Windows,
sem exportar a chave privada. Tokens A3 e smart cards dependem do driver/provedor do
fabricante, que deve expor a chave ao Windows. O PIN permanece sob controle desse provedor.
Os testes cobrem chaves CNG não exportáveis; um token físico específico precisa ser
testado com seu driver e o titular presente.

O motor de cadeias do Windows confere assinatura, datas, restrições e revogação de
toda a cadeia subordinada. A consulta utiliza LCR/OCSP e o cache verificado do sistema.
O aplicativo não importa raízes, instala certificados ou modifica a confiança do sistema.

- **Qualificada:** caminho válido até uma das raízes ICP-Brasil exatas incluídas,
  política de certificado de assinatura A1–A4 e revogação confirmada para toda a cadeia.
  O selo mostra **Assinatura qualificada (com raiz na ICP-Brasil)**.
- **Gov.br de referência:** caminho até a raiz exata já identificada. Não recebe a
  classificação qualificada ICP-Brasil.
- **Outras raízes ou verificação incompleta:** selo genérico, sem classificação qualificada.
- **Revogação confirmada:** operação bloqueada.

**Verifique em https://validar.iti.gov.br** aparece somente com uma cadeia identificada
até uma raiz ICP-Brasil incluída ou a raiz Gov.br exata. O nome de uma autoridade não
é usado como prova de confiança. A classificação é separada da identificação da raiz:
uma falha de consulta de revogação nunca produz um selo qualificado.

Detalhes e procedência das autoridades públicas: [ICP-Brasil](icp-brasil-roots.md) e
[Gov.br](gov-br-root.md). As autoridades devem ser revisadas antes de cada distribuição.

O perfil é **PAdES Baseline B**, `ETSI.CAdES.detached`, em atualização incremental.
Assinaturas anteriores permanecem nas revisões anteriores. PDFs certificados com
DocMDP ou bloqueios FieldMDP são recusados. PDFs que exigem senha não são suportados.
Não são incluídos carimbo de tempo TSA, evidências LTV ou política explícita de assinatura
ICP-Brasil. A data usa o relógio e o fuso do computador. O texto do selo não constitui
homologação pelo ITI nem substitui a avaliação de um validador independente.

## Privacidade

Os PDFs, a imagem do selo e a chave privada permanecem no computador. A rede é usada
somente pelo Windows para obter certificados emissores e verificar revogação. Nenhum
PDF é enviado ao VALIDAR ou a um serviço remoto. Não há telemetria do aplicativo.
As cópias de trabalho ficam em uma pasta temporária exclusiva da sessão e são removidas
ao fechar normalmente. Uma interrupção abrupta pode deixar essa pasta temporária.

## Compilar e testar

Instale o **SDK .NET 10** e execute na raiz deste projeto:

```powershell
dotnet restore Assinador.Windows.slnx --locked-mode
dotnet test Assinador.Windows.slnx --no-restore
dotnet run --project src/Assinador.Windows
```

Para gerar o pacote portátil completo, com testes:

```powershell
./build.ps1
```

Saídas:

- `artifacts/publish/win-x64/Assinador.Windows.exe`: aplicativo e dependências.
- `artifacts/assinador-windows-0.1.3-win-x64.zip`: pacote portátil.
- `artifacts/test-results/`: resultados dos testes.

Os testes criam certificados e chaves temporários próprios, sem importar certificados
nos armazenamentos pessoais ou acessar credenciais do usuário. A verificação de
revogação usa um servidor HTTP de teste acessível somente pelo loopback.
Para testar um PDF local adicional e preservar evidências somente em artifacts:

```powershell
$env:ASSINADOR_TEST_PDF = (Resolve-Path 'artifacts/test-inputs/Acervo total.pdf').Path
$env:ASSINADOR_EVIDENCE_DIR = Join-Path $PWD 'artifacts/desktop-tests'
dotnet test Assinador.Windows.slnx
```

## Organização e integração contínua

- `src/Assinador.Core/`: identidade, autoridades públicas, confiança, coordenadas e assinatura.
- `src/Assinador.Windows/`: WPF, prévia nativa, selo e seleção de certificados.
- `tests/Assinador.Tests/`: testes criptográficos, de revogação, arquivos e renderização.
- `.github/workflows/windows.yml`: testes e geração do pacote em Windows, com actions fixadas por commit.
- `artifacts/`: binários, relatórios, PDFs e evidências locais, ignorados pelo Git.

O workflow executa em push, pull request ou manualmente. O pacote fica em **Actions →
execução → Artifacts → assinador-windows-win-x64**, por 14 dias.
Não usa certificados pessoais, segredos de publicação ou o PDF local de teste.
O projeto não contém histórico Git nem referências ao projeto que originou a aplicação.

## Código aberto e referências

Licença **GNU AGPL v3 (AGPL-3.0-only)**: [LICENSE](LICENSE), [NOTICE](NOTICE).
Distribua o código-fonte correspondente, preserve os avisos do iText e o Producer
inserido nos PDFs. O certificado que assina documentos é independente de uma eventual
assinatura Authenticode do executável da aplicação.

- [PAdES com iText](https://kb.itextpdf.com/itext/pades-signing-high-level-api).
- [APIs Windows Runtime em aplicações desktop](https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/desktop-to-uwp-enhance).
- [Confiança personalizada do Windows](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509chainpolicy.trustmode).
- [Motor de PDFs do Windows](https://learn.microsoft.com/en-us/uwp/api/windows.data.pdf.pdfdocument).
