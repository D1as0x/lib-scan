# lib-scan

Scanner de vulnerabilidades conhecidas em bibliotecas JavaScript. Analisa
arquivos `.js`/`.mjs`, manifestos de dependências (`package.json`,
`package-lock.json`, `yarn.lock`) e páginas web, comparando os componentes
encontrados com a base de definições do [RetireJS](https://github.com/RetireJS/retire.js).

Para cada vulnerabilidade encontrada, o relatório inclui severidade, versão
afetada, versão corrigida, CVEs e links para o NVD (NIST) e Snyk.

## Requisitos

- Python 3.6+ (usa apenas a biblioteca padrão)
- Acesso à internet para baixar a base de definições — a menos que use `--offline`
- **Opcional**, apenas para a exportação `--cve-docx`:
  - Node.js
  - A biblioteca `docx` instalada na pasta do script: `npm install docx`

## Instalação

```bash
git clone git@github.com:D1as0x/lib-scan.git
cd lib-scan
```

Para habilitar a exportação em `.docx` (opcional):

```bash
npm install docx
```

> A biblioteca `docx` precisa estar instalada **na mesma pasta do `js-scan.py`**,
> pois é a partir dela que o Node resolve o módulo.

## Uso

```bash
python3 js-scan.py <caminho> [opções]
```

`<caminho>` pode ser um arquivo ou um diretório (percorrido recursivamente).

### Exemplos

Escanear um diretório de projeto:

```bash
python3 js-scan.py ./meu-projeto
```

Escanear uma página web e os scripts que ela carrega:

```bash
python3 js-scan.py -u https://exemplo.com
```

Escanear um arquivo `.js` remoto:

```bash
python3 js-scan.py -u https://cdn.exemplo.com/jquery.min.js
```

Saída em JSON (para integração com outras ferramentas):

```bash
python3 js-scan.py ./meu-projeto --json
```

Falhar o pipeline de CI se houver vulnerabilidade de severidade alta ou maior:

```bash
python3 js-scan.py ./meu-projeto --fail-on high
```

Modo offline usando bases locais:

```bash
python3 js-scan.py ./meu-projeto --offline --db jsrepo.json,npmrepo.json
```

Gerar um documento com os CVEs clicáveis (ver seção abaixo):

```bash
python3 js-scan.py ./meu-projeto --cve-docx
```

## Opções

| Opção | Descrição |
|---|---|
| `path` | Arquivo ou diretório a escanear. |
| `-u`, `--url URL` | URL a escanear (arquivo `.js` ou página HTML). Pode ser repetida. |
| `--json` | Saída em formato JSON. |
| `--cve-docx` | Gera `cves.docx` com os CVEs como hyperlinks para o NIST. |
| `--no-color` | Desativa as cores no terminal. |
| `--offline` | Usa bases locais (via `--db`) em vez de baixar. |
| `--db ARQUIVOS` | Arquivo(s) de definições locais, separados por vírgula. |
| `--fail-on NÍVEL` | Sai com código diferente de zero se houver achado com severidade `>=` ao nível dado (`critical`, `high`, `medium`, `low`, `none`). |

## Exportar CVEs para o Google Docs

A opção `--cve-docx` gera um arquivo `cves.docx` contendo apenas os CVEs
encontrados, sem duplicatas, cada um como um link clicável que leva à página
correspondente no NVD (NIST). O arquivo é gerado na pasta em que você está.

```bash
python3 js-scan.py ./meu-projeto --cve-docx
```

Para usar no Google Docs mantendo os links:

1. Arraste o `cves.docx` para o Google Drive.
2. Clique com o botão direito no arquivo → **Abrir com** → **Documentos Google**.

Os CVEs já aparecem como hyperlinks. Se precisar copiar esse conteúdo para
outro documento, copie de dentro do próprio Google Docs (e não do arquivo
original), para preservar a formatação.

> Esta opção requer Node.js e a biblioteca `docx` instalada na pasta do script
> (`npm install docx`). Se o módulo não for encontrado, a ferramenta indica o
> caminho exato onde rodar o comando.


## Como funciona

O scanner detecta a versão de cada biblioteca por três métodos: correspondência
no nome do arquivo, padrões no conteúdo do arquivo e hash SHA-1 do conteúdo.
Para manifestos, lê as versões declaradas nas dependências. As versões
detectadas são comparadas com as faixas de versão vulneráveis de cada
definição (`atOrAbove`, `above`, `below`, `atOrBelow`).

## Fontes de dados

- Definições JS: `RetireJS/retire.js` — `jsrepository.json`
- Definições npm: `RetireJS/retire.js` — `npmrepository.json`

## Aviso

A ferramenta reporta apenas vulnerabilidades *conhecidas* presentes na base de
definições. A ausência de achados não garante que o código seja seguro.
