# Raiz Gov.br de referência

A assinatura do documento de referência fornecido pelo usuário foi conferida com iText:
uma assinatura, integridade criptográfica válida e cobertura do documento inteiro.
O CMS incorporava somente o certificado do titular. A cadeia foi completada pelo
pacote público indicado na extensão AIA do certificado e o encadeamento de assinaturas
foi validado até a raiz, considerando a data declarada da assinatura.
Essa inspeção identificou a raiz; não constitui um relatório completo de revogação
ou de conformidade da assinatura do documento de referência.

## Cadeia identificada

1. Certificado do signatário.
2. **AC Final do Governo Federal do Brasil v1**.
3. **AC Intermediaria do Governo Federal do Brasil v1**.
4. **Autoridade Certificadora Raiz do Governo Federal do Brasil v1**.

Esta é a cadeia de assinaturas eletrônicas avançadas do Gov.br, independente da
infraestrutura ICP-Brasil, conforme o [relatório oficial do ITI](https://www.gov.br/iti/pt-br/acesso-a-informacao/auditorias/relatorios-de-gestao/ITI_RelatoriodeGestao_2023.pdf).
Ela não recebe a classificação de assinatura qualificada ICP-Brasil no aplicativo.

## Identificação exata da raiz

```text
Subject / Issuer:
CN=Autoridade Certificadora Raiz do Governo Federal do Brasil v1,
OU=Instituto Nacional de Tecnologia da Informacao - ITI,O=Gov-Br,C=BR

SHA-256 do certificado em DER:
163BD003BC0DF2BEAB88174B6D5B450B6E1DC973A64B2DC2A33218544F49EF4E

Validade final: 10/06/2033
```

A comparação usa o certificado raiz exato, com esse SHA-256, e um caminho PKIX válido.
Um certificado com nome semelhante e outra chave não é aceito.

## Procedência dos certificados públicos

- Endereço AIA: `http://repo.iti.br/docs/Cadeia_GovBr-der.p7b`.
- Conferência independente: distribuição HTTPS indicada na
  [página oficial de importação da cadeia Gov.br](https://www.gov.br/governodigital/pt-br/identidade/assinatura-eletronica/saiba-como-importar-os-certificados-do-gov-br-no-adobe-acrobat-reader),
  hospedada em [arquivos.ufsc.br](https://arquivos.ufsc.br/f/011077a80362419997c3/?dl=1).
- Os pacotes obtidos pelos dois canais em 18/11/2026 foram idênticos.
- SHA-256 do pacote P7B: `DBF22F7C15ACE9C37E6B4141271695A17DC445B5A04C003CED94322AD905879F`.

Somente as três autoridades públicas são incluídas em `src/Assinador.Core/Assets/Authorities/GovBr/`.
O documento de referência e o certificado pessoal do seu titular não são incluídos
no código-fonte ou no executável.

## Regra do endereço VALIDAR no selo

O texto `Verifique em https://validar.iti.gov.br` é exibido somente quando a cadeia
alcança uma das raízes ICP-Brasil incluídas ou a raiz Gov.br exata descrita acima.
Outras raízes e a prévia antes da seleção de um certificado não exibem esse endereço.
A identificação da raiz é separada da verificação de revogação e da classificação
qualificada: uma raiz Gov.br reconhecida nunca torna a assinatura qualificada ICP-Brasil.
