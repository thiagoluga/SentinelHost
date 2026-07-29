# Corpus de teste

Este diretório existe para validar o **motor de consenso**, não para validar a
capacidade de detecção de nenhum engine.

## Regra absoluta: nada aqui é malware vivo

A constituição do projeto proíbe malware executável no repositório. Todas as
amostras em `sintetico/` são **inertes por construção**:

- reproduzem a **estrutura** de um padrão malicioso (concatenação ofuscada,
  callback dinâmico, blob base64, upload sem validação), mas
- **nunca** montam uma chamada executável funcional, e
- carregam o marcador `SENTINELHOST-SYNTHETIC-CORPUS` em texto claro.

[`AMOSTRAS.md`](AMOSTRAS.md) documenta, uma a uma, o que cada amostra simula,
por que ela é inofensiva e qual categoria/severidade/confiança do esquema
normalizado ela deveria receber. Ver `DECISIONS.md` D-010.

Se você abrir uma dessas amostras num navegador ou passá-la a `php`, ela imprime
um aviso e termina. Ela não abre shell, não escreve arquivo, não faz rede.

## Estrutura

```text
corpus/
├── sintetico/          amostras que o consenso DEVE apontar
├── limpo/              arquivos legítimos que o consenso NÃO pode apontar
├── AMOSTRAS.md         o que cada amostra simula e por que é inerte
└── manifesto.json      expectativa por arquivo, lida pelo teste do SC-001
```

`limpo/` contém arquivos que costumam gerar falso positivo em scanner de
malware: PHP legítimo com `base64_encode` (uso normal), JS minificado, e um
arquivo de core do WordPress cujo hash bate com o checksum oficial. Detectar
qualquer um deles como `confirmed` reprova o SC-001.

## Antivírus de estação de trabalho

Um antivírus pode reagir a este diretório mesmo com amostras inertes — a
heurística acerta no formato, não na intenção. Se o clone do repositório vier
incompleto no Windows, adicione uma exclusão para a pasta do repositório.
Nenhuma amostra aqui pode causar dano, mas essa afirmação você deve verificar
lendo os arquivos, não confiando neste README.

## O que este corpus NÃO é

Não é um benchmark de detecção. Os engines reais (AMWScan, php-malware-finder,
maldet) não são executados nos testes automatizados — ver `DECISIONS.md` D-011.
O SC-001 é verificado com adaptadores de teste que emitem `ScanReport` fixos,
porque o que está sob teste é a consolidação por consenso, não a assinatura de
terceiros.
