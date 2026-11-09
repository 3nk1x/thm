# Room 1: The Building Blocks of AI
Path: AI Security → AI Fundamentals | Completed: 2026-10-03

## One-line memory version
> AI learns from examples (4 ways to teach). A neural network is a factory: eyes → thinking → decision. ChatGPT is a giant autocomplete that can be tricked.

## The big picture
- **AI** = getting computers to act smart like humans.
- **Machine Learning (ML)** = learning from examples instead of a rulebook.
- Hierarchy: **AI ⊃ ML ⊃ Deep Learning ⊃ LLMs**
- Every ML algorithm loops: **decision process → error function → model optimisation**

## The 4 ways to learn
| Type | Teaching style | Remember it as | Clue words |
|---|---|---|---|
| **Supervised** | Flashcards with the answer on the back | "Teacher with answer key" | labelled, marked, known answers |
| **Unsupervised** | Pile of LEGO, "sort these" | "Figure it out yourself" | no labels, clusters, anomalies |
| **Semi-supervised** | Label a few, sort the rest | "A little help, then on your own" | small labelled + large unlabelled |
| **Reinforcement** | Treats and time-outs | "Treats and time-outs" | rewards, penalties, score, actions |

## Neural networks = a factory with 3 rooms
1. **Input layer (eyes)**: raw facts only, no opinions. 1 node per pixel (4x4 image = 16 nodes).
2. **Hidden layer (thinking)**: finds patterns (edges, shapes, curves).
3. **Output layer (decision)**: highest score wins.

- Connections = **synapses** (roads), each with a **weight** (how much it counts).
- **More than 3 layers = Deep Learning**. Doesn't need labelled data, so it scales.

## LLMs (ChatGPT etc.) = super-powered autocomplete
- Predicts **the next word**, over and over.
- **Pre-training**: guess the missing word trillions of times.
- **Parameters**: billions of numbers that store what it learned.
- **Backpropagation**: the self-correcting step that adjusts parameters after a wrong guess.
- **Transformer neural networks**: the brain design (Google, 2017, "Attention is All You Need").
- **Attention**: weighs which words matter ("it" → "the bank", not "the loan").
- **RLHF** (Reinforcement Learning from Human Feedback): humans grade answers, teaching it manners.

## Why a hacker cares
- It only **predicts**, so it can **hallucinate** (confidently make things up).
- It pays **attention to everything** you feed it → hidden instructions can trick it = **prompt injection**.
- RLHF trains refusals → **jailbreaks** try to get around them.

## Lessons from the challenges
- Flags come from the **Open Agent** chat or **View Site**, not the page text. Format: `THM{...}`.
- Each agent tab belongs to ONE task, so put each flag in the right task's box.
- **Copy-paste** flags, don't retype them (0/O, 1/l mix-ups).
- **Count the underscores** in answer boxes: each group = one word, length = letters.
- Scripted bots want their **exact format**. Copy their template, keep answers short.
