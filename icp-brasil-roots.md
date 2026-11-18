# Âncoras ICP-Brasil

Certificados públicos obtidos em **18/11/2026** nos links do
[repositório oficial AC-Raiz do ITI](https://www.gov.br/iti/pt-br/assuntos/repositorio/repositorio-ac-raiz).
Os arquivos avulsos são publicados pelo ITI em
`http://acraiz.icpbrasil.gov.br/credenciadas/RAIZ/ICP-Brasilv<VERSAO>.crt`.
O serviço de download não aceitou HTTPS na preparação dos arquivos incluídos.
Os resumos abaixo correspondem ao certificado em **DER**, independentemente da codificação
PEM usada no arquivo distribuído. Revisores devem conferir estas âncoras em canal oficial
independente antes de publicar uma versão de produção.

| Raiz | SHA-256 (DER) | Validade final |
| --- | --- | --- |
| v4 | `F0C15AFD258FB674E7A96E1A50FF873149364B9EC70D4D93C7A9F1EB6060D020` | 23/04/2035 |
| v5 | `CAA53FC6091C6951887C976E378F6EF89AA6377C55D97B6475422B71ED7E9B17` | 02/03/2029 |
| v6 | `3BDB9B509352F1D3D71C2BF64D9A38A4E6CEBDA27809D77F7AC476CBDE6E314A` | 28/12/2038 |
| v7 | `5657E70580EB678983F3ED7DFCE091D84CAE6549389A47FCCDA8D0E4DC2CF576` | 28/12/2038 |
| v12 | `D8478E37CE19C690CF657381E68FE600E4E1A042536830F06847E03E554C4B01` | 22/10/2037 |
| v13 | `2B07D0BC02C4A6E0478ED22D0D99E8F97E1827B269097696A7FEB6AAD30C3AC8` | 14/02/2045 |

Não foram incluídas as raízes expiradas, as revogadas v3/v8/v9, a v10 destinada a SSL
nem a v11 destinada a assinatura de código. A confiança usa exclusivamente os arquivos
incluídos no aplicativo, sem importar raízes instaladas pelo usuário.

A lista deve ser revisada contra o ITI a cada distribuição: uma raiz pode ser substituída
ou deixar de ser confiável antes de vencer. A consulta de LCR do caminho verifica os
certificados subordinados; a manutenção das âncoras é responsabilidade da distribuição.
