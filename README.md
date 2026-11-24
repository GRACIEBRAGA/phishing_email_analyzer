# Phishing Email Analyzer

A Python tool that analyzes a saved email (`.eml`) and checks the classic signs of phishing: sender spoofing, SPF / DKIM / DMARC results, links that hide their real destination, dangerous attachments, pressure language and requests for personal data. Each result is mapped to **MITRE ATT&CK T1566** and to awareness and filtering controls (ISO 27001, NIST CSF 2.0).

It is **safe by design**: it only reads the text of the file. It never opens links or runs attachments, and links in the report are defanged (`hxxp://site[.]com`).

- **Requirements:** Python 3.11 or newer. No extra libraries needed.
- **Usage:** `python analyze_email.py suspicious.eml`

## Case study: a "suspicious" email that turned out to be real

I kept receiving an email from a Brazilian bank asking me to reply with my ID number (CPF), name and phone to negotiate a debt, even after blocking the sender. I was sure it was phishing.

The analysis showed something different:

- SPF, DKIM and DMARC all **passed** for the bank's official domain.
- The `Received` headers showed the email travelled only through the bank's own servers.
- But the message was addressed to **another customer**: my email address was registered by mistake on someone else's contract. That's why blocking didn't stop it.

**Verdict: not phishing, but two real risks.** The bank asks for personal data by email reply (exactly what scammers imitate), and another customer's personal data was being delivered to the wrong person (a privacy incident under LGPD).

While analyzing it, I noticed the tool didn't flag the request for personal data, so I added a new check (`Asks for personal data by email`). Lesson: not every suspicious email is phishing, and the decision has to come from evidence, not impressions.

> The real email is not included in this repository because it contains personal data. The `examples/` folder has a fictional phishing email instead.

---

# Guia passo a passo (PT-BR)

Guia para fazer uma análise completa sozinha, do começo ao fim.

## Regras de segurança (sempre)

1. **Nunca clique** nos links nem abra os anexos do e-mail suspeito.
2. **Nunca responda** o e-mail, principalmente com dados pessoais.
3. **Nunca suba** um `.eml` real para o GitHub: ele tem o seu e-mail e, às vezes, dados de outras pessoas. O arquivo `.gitignore` deste projeto já bloqueia isso.
4. Em prints para redes sociais, **esconda** o seu e-mail (linhas `Delivered-To` e `for <...>`) e qualquer nome, CPF ou dado de terceiros.

## Passo 1: preparar a pasta

Coloque o `analyze_email.py` e o e-mail baixado **na mesma pasta** (por exemplo, `Downloads`).

## Passo 2: baixar o e-mail suspeito

- **Gmail:** abra o e-mail → clique nos **três pontinhos (⋮)** ao lado do botão de responder → **Fazer o download da mensagem**. Será salvo um arquivo `.eml`.
- **Outlook (web):** abra o e-mail → **três pontinhos (...)** → **Salvar como** ou **Download**.

## Passo 3: abrir o terminal na pasta certa

No VS Code: **Terminal → New Terminal**. Depois, um comando de cada vez:

```powershell
cd Downloads
```

Ver os e-mails `.eml` que estão na pasta (e o nome exato de cada um):

```powershell
dir *.eml
```

## Passo 4: rodar a análise

Troque o nome pelo nome real do arquivo, **entre aspas**:

```powershell
python analyze_email.py "NOME DO ARQUIVO.eml"
```

Dica: digite as primeiras letras do nome e aperte **Tab** para o terminal completar sozinho.

O resultado aparece na tela e também é salvo no arquivo `phishing_report.md`.

## Passo 5: análise manual do cabeçalho

O script ajuda, mas o analista sempre confere. Abra o `.eml` no VS Code (**File → Open File**, filtro **All Files**) e procure com **Ctrl+F**:

| Procure | O que significa | Sinal de alerta |
|---|---|---|
| `From:` | Quem diz que enviou | Nome de empresa conhecida com domínio estranho (ex: "Receita Federal" `<x@receita-regulariza.top>`) |
| `Reply-To:` | Para onde vai a sua resposta | Domínio diferente do `From:` |
| `Return-Path:` | Para onde voltam respostas automáticas | Domínio diferente do `From:` |
| `Authentication-Results` | Resultado das verificações feitas pelo seu provedor | `spf`, `dkim` ou `dmarc` diferente de `pass` |
| `header.i=` ou `header.d=` (dentro do DKIM) | Quem assinou o e-mail | Domínio diferente do `From:` |
| `Received: from` | Por quais servidores o e-mail passou (leia de baixo para cima) | Servidores que não pertencem à empresa |
| `To:` | Para quem foi enviado | `undisclosed-recipients` indica envio em massa |
| Texto do e-mail | O que ele pede | Pedido de CPF, senha, cartão, código; urgência; ameaça |

### O que é SPF, DKIM e DMARC (resumo)

- **SPF:** o servidor que enviou tem permissão para enviar em nome desse domínio?
- **DKIM:** o e-mail tem uma assinatura digital válida do domínio?
- **DMARC:** o dono do domínio diz o que fazer quando as verificações falham, e o `From:` bate com quem foi verificado?

Analogia: é como conferir uma nota fiscal. O emitente existe, a assinatura é válida e os dados batem?

## Passo 6: entender o resultado do script

| Linha | O que observar |
|---|---|
| `Sender domain` | É o domínio oficial da empresa? |
| `Authentication` | As três como `pass` indicam que o e-mail veio mesmo desse domínio |
| `Sending server` | O último servidor antes do seu provedor. Pertence à empresa? |
| `Links found` | Quantos links. Veja na tabela se algum é suspeito |
| `Verdict` | `LIKELY PHISHING` (6 pontos ou mais), `SUSPICIOUS` (3 a 5), `NO STRONG SIGNS` (0 a 2) |

O que cada verificação da tabela significa:

| Verificação | Risco | Significado |
|---|---|---|
| Brand impersonation | Alto | Diz ser uma empresa conhecida, mas veio de outro domínio |
| DMARC not passed | Alto | O domínio não confirmou que o e-mail é dele |
| SPF / DKIM not passed | Médio | Servidor não autorizado ou assinatura inválida |
| Reply-To / Return-Path differs | Médio | A resposta iria para outro lugar |
| Link to a raw IP address | Alto | Link para um número (IP), e não para um site |
| Link text differs from real destination | Alto | O link mostra um endereço e leva para outro |
| Shortened link | Médio | Encurtador esconde o destino real |
| Dangerous attachment | Alto | Anexo que pode executar programa (`.exe`, `.pdf.exe`, `.zip`...) |
| Asks for personal data by email | Médio | Pede CPF, senha, cartão ou telefone por resposta |
| Pressure / urgency language | Baixo/Médio | Palavras de pressão: "urgente", "bloqueado", "regularize" |

## Passo 7: checklist de perguntas para o veredito

Responda antes de concluir:

1. O domínio do remetente é o oficial da empresa?
2. SPF, DKIM e DMARC passaram?
3. O DKIM foi assinado pelo mesmo domínio do `From:`?
4. O `Reply-To` e o `Return-Path` são do mesmo domínio?
5. Os servidores no `Received` pertencem à empresa?
6. Os links levam para onde dizem levar?
7. Existe anexo perigoso?
8. O e-mail pede dados pessoais, senha ou pagamento?
9. O e-mail é mesmo para mim (nome, contrato, dados batem)?
10. A urgência faz sentido, ou é pressão para eu agir sem pensar?

### Os três vereditos possíveis

- **Phishing:** falha de autenticação, domínio falso, links ou anexos maliciosos. Ação: não interagir, denunciar como phishing e apagar.
- **Legítimo:** autenticação aprovada, domínio e servidores oficiais, nada pedido de forma arriscada.
- **Legítimo com risco:** veio mesmo da empresa, mas tem uma prática perigosa (pede dados por e-mail, chegou para a pessoa errada). Ação: não responder com dados e usar os canais oficiais, digitando o endereço do site você mesma.

Atenção: autenticação aprovada **não é garantia absoluta**. Se a conta de e-mail verdadeira de uma empresa for invadida, o golpe sai do servidor real e passa em todas as verificações. Esse ataque se chama **BEC (Business Email Compromise)**. Por isso a análise do conteúdo (pergunta 8) continua importante.

## Problemas comuns

| Erro | Causa | Solução |
|---|---|---|
| `O termo '.eml' não é reconhecido` | Digitou o nome do arquivo como se fosse um comando | Use `python analyze_email.py "arquivo.eml"` |
| `FileNotFoundError: No such file or directory` | Nome errado, ou o e-mail não está na mesma pasta | Rode `dir *.eml`, copie o nome exato e use aspas |
| `can't open file ... analyze_email.py` | O terminal está em outra pasta | `cd Downloads` (ou a pasta do script) |
| Alterei o código e o resultado não mudou | Editou uma cópia diferente da que o terminal roda | No terminal, `code analyze_email.py` abre exatamente o arquivo da pasta atual |
| `SyntaxError: f-string expression part cannot include a backslash` | Versão do Python menor que 3.11/3.12 com código novo | Atualize o Python ou use a versão deste repositório |

Para conferir se uma alteração está mesmo no arquivo:

```powershell
Select-String -Path analyze_email.py -Pattern "texto que você adicionou"
```

## Testar com o exemplo fictício

```powershell
cd examples
python ../analyze_email.py sample_phishing_receita.eml
```

O resultado esperado está em `examples/sample_report.md` (veredito `LIKELY PHISHING`).

## Skills demonstrated

Email header analysis · SPF / DKIM / DMARC · Phishing triage (true vs. false positive) · Python · MITRE ATT&CK T1566 · LGPD · Security awareness
