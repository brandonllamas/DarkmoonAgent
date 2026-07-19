# Modelos Ollama para Ingeniería Inversa y Hacking

Guía de modelos recomendados para usar con `agent.py` y `agent_ing.py`.
Todos se instalan con: `ollama pull <nombre>`

---

python3 agent.py --web --deepseek --verbose

## ⭐ Recomendados para Ingeniería Inversa (RE)

### 1. deepseek-r1:14b ← MEJOR OPCIÓN ACTUAL

```
ollama pull deepseek-r1:14b
```

- **Por qué**: Razonamiento paso a paso (chain-of-thought), excelente para analizar
  binarios, entender flujos de código y decidir técnicas de bypass.
- **Censura**: Baja — tolera análisis de malware, exploits, RE de binarios protegidos.
- **Contexto**: 64K tokens — puede procesar output largo de `strings`/`nm`/`r2`.
- **RAM necesaria**: ~10 GB VRAM / 12 GB RAM
- **Velocidad**: Media (vale la pena la espera)
- **Uso en agente**: `python3 agent_ing.py --model deepseek-r1:14b`

### 2. deepseek-r1:32b

```
ollama pull deepseek-r1:32b
```

- **Por qué**: Versión grande de deepseek-r1. Mejor razonamiento sobre código complejo,
  Cython, PyInstaller, binarios obfuscados.
- **Censura**: Baja — igual que 14b, muy permisivo con temas de seguridad.
- **Contexto**: 64K tokens
- **RAM necesaria**: ~20 GB VRAM / 24 GB RAM
- **Velocidad**: Lenta
- **Uso en agente**: `python3 agent_ing.py --model deepseek-r1:32b`

### 3. deepseek-coder-v2:16b

```
ollama pull deepseek-coder-v2:16b
```

- **Por qué**: Entrenado específicamente en código. Entiende ASM, C, Python, Cython.
  Ideal para analizar output de r2/ghidra y generar patches precisos.
- **Censura**: Muy baja — orientado a código, no tiene filtros de seguridad agresivos.
- **Contexto**: 128K tokens
- **RAM necesaria**: ~12 GB VRAM
- **Velocidad**: Media

### 4. qwen2.5-coder:14b

```
ollama pull qwen2.5-coder:14b
```

- **Por qué**: Muy bueno para análisis de código, genera C/Python/bash correctos.
  Excelente para escribir el código de bypass (LD_PRELOAD, patches).
- **Censura**: Baja-media — modelo chino, menos restricciones que modelos occidentales.
- **Contexto**: 128K tokens
- **RAM necesaria**: ~10 GB VRAM
- **Velocidad**: Rápida

---

## 🐬 Serie Dolphin (EXPLÍCITAMENTE sin censura)

Los modelos Dolphin son finetunings que eliminan el RLHF (filtros de seguridad).
Son los más permisivos disponibles en Ollama.

### 5. dolphin-mistral:latest ← YA INSTALADO

```
ollama pull dolphin-mistral:latest
```

- **Censura**: NINGUNA — sin filtros, responde cualquier consulta de RE/hacking/malware.
- **Contexto**: 8192 tokens ⚠️ MUY PEQUEÑO — problem con prompts largos del agente.
- **RAM necesaria**: ~5 GB VRAM / 6 GB RAM
- **Velocidad**: Muy rápida
- **Limitación**: El contexto pequeño causa bucles infinitos en agent_ing.py cuando
  el análisis inicial (strings+nm+r2) supera ~4000 tokens. Usar solo para consultas cortas.

### 6. dolphin3:8b

```
ollama pull dolphin3:8b
```

- **Por qué**: Versión mejorada de Dolphin, basada en Llama 3.1. Más inteligente que
  dolphin-mistral con el mismo nivel de permisividad.
- **Censura**: NINGUNA
- **Contexto**: 131K tokens ✅ — sin el problema de contexto de dolphin-mistral.
- **RAM necesaria**: ~6 GB VRAM
- **Velocidad**: Rápida
- **Uso recomendado**: Reemplaza a dolphin-mistral en el agente.

### 7. dolphin-llama3:8b

```
ollama pull dolphin-llama3:8b
```

- **Por qué**: Llama 3 sin censura. Buen equilibrio entre velocidad y calidad.
- **Censura**: NINGUNA
- **Contexto**: 8192 tokens ⚠️ pequeño (mismo problema que dolphin-mistral)
- **RAM necesaria**: ~6 GB VRAM
- **Velocidad**: Rápida

### 8. dolphin-mixtral:8x7b

```
ollama pull dolphin-mixtral:8x7b
```

- **Por qué**: Mixtral MoE sin censura — arquitectura de mezcla de expertos,
  mejor razonamiento que dolphin-mistral con el mismo espíritu de libertad total.
- **Censura**: NINGUNA
- **Contexto**: 32K tokens ✅
- **RAM necesaria**: ~30 GB RAM (usa CPU offload)
- **Velocidad**: Lenta en CPU, rápida con VRAM suficiente

---

## 🔓 Otros modelos sin censura / permisivos

### 9. nous-hermes2:10.7b

```
ollama pull nous-hermes2:10.7b
```

- **Por qué**: Nous Research produce modelos muy capaces y sin filtros agresivos.
  Excelente para razonamiento sobre seguridad.
- **Censura**: Baja
- **Contexto**: 4096 tokens ⚠️ pequeño
- **RAM necesaria**: ~8 GB VRAM

### 10. wizard-vicuna-uncensored:13b

```
ollama pull wizard-vicuna-uncensored:13b
```

- **Por qué**: Modelo antiguo pero explícitamente sin censura, útil para tareas
  de RE donde otros modelos se niegan.
- **Censura**: NINGUNA
- **Contexto**: 4096 tokens ⚠️ muy pequeño
- **RAM necesaria**: ~9 GB RAM
- **Nota**: Modelo de 2023, menor calidad que alternativas modernas.

### 11. llama3.1:8b

```
ollama pull llama3.1:8b
```

- **Por qué**: Meta Llama 3.1 — aunque tiene algo de censura, es bastante permisivo
  con temas de RE/seguridad si se formula bien la pregunta.
- **Censura**: Media-baja
- **Contexto**: 128K tokens ✅
- **RAM necesaria**: ~6 GB VRAM
- **Velocidad**: Rápida

### 12. mistral:7b

```
ollama pull mistral:7b
```

- **Por qué**: El modelo base de Mistral tiene poca censura. Genera comandos de
  bash/python correctos. Base del dolphin-mistral.
- **Censura**: Baja
- **Contexto**: 32K tokens ✅
- **RAM necesaria**: ~5 GB VRAM
- **Velocidad**: Muy rápida

---

## 📊 Tabla comparativa rápida

| Modelo                 | Censura  | Ctx   | RAM  | Velocidad  | RE Score   |
| ---------------------- | -------- | ----- | ---- | ---------- | ---------- |
| deepseek-r1:14b        | Baja     | 64K   | 12GB | Media      | ⭐⭐⭐⭐⭐ |
| deepseek-r1:32b        | Baja     | 64K   | 24GB | Lenta      | ⭐⭐⭐⭐⭐ |
| deepseek-coder-v2:16b  | Muy baja | 128K  | 12GB | Media      | ⭐⭐⭐⭐⭐ |
| dolphin3:8b            | Ninguna  | 131K  | 6GB  | Rápida     | ⭐⭐⭐⭐   |
| qwen2.5-coder:14b      | Baja     | 128K  | 10GB | Rápida     | ⭐⭐⭐⭐   |
| dolphin-mixtral:8x7b   | Ninguna  | 32K   | 30GB | Lenta      | ⭐⭐⭐⭐   |
| dolphin-mistral:latest | Ninguna  | 8K ⚠️ | 6GB  | Muy rápida | ⭐⭐       |
| mistral:7b             | Baja     | 32K   | 5GB  | Muy rápida | ⭐⭐⭐     |
| llama3.1:8b            | Media    | 128K  | 6GB  | Rápida     | ⭐⭐⭐     |

---

## 🎯 ¿Cuál usar para cada tarea?

**Ingeniería inversa de binarios (agent_ing.py)**
→ `deepseek-r1:14b` — mejor razonamiento para decidir técnica de bypass
→ `dolphin3:8b` — si quieres velocidad y sin censura, contexto grande

**Pentesting web (agent.py)**
→ `deepseek-r1:14b` — razonamiento para encadenar exploits
→ `qwen2.5-coder:14b` — genera payloads/scripts precisos

**Análisis de código ofuscado / Cython**
→ `deepseek-coder-v2:16b` — especializado en código, entiende ASM/C
→ `deepseek-r1:32b` — si tienes RAM, el más capaz

**Binarios con protecciones fuertes (anti-debug, packer)**
→ `deepseek-r1:32b` — mayor contexto de razonamiento
→ `dolphin-mixtral:8x7b` — sin censura + razonamiento MoE

**Hardware limitado (< 8 GB RAM)**
→ `dolphin3:8b` o `mistral:7b` — menor consumo con contexto decente

---

## ⚙️ Configuración en .env

```ini
# Cambiar modelo por defecto para los agentes
OLLAMA_URL=http://192.168.80.120:11434/api/chat
```

Para usar un modelo específico en los agentes:

```bash
# agent.py
python3 agent.py --model dolphin3:8b

# agent_ing.py
python3 agent_ing.py --target /ruta/binario --model deepseek-r1:14b
```

---

## 📥 Instalar todos los recomendados

```bash
# Imprescindibles (ya instalados o recomendados)
ollama pull deepseek-r1:14b
ollama pull deepseek-coder-v2:16b
ollama pull dolphin3:8b

# Opcionales
ollama pull qwen2.5-coder:14b
ollama pull mistral:7b
ollama pull llama3.1:8b

# Solo si tienes +24 GB RAM
ollama pull deepseek-r1:32b
ollama pull dolphin-mixtral:8x7b
```

Ver modelos instalados:

```bash
ollama list
```

Ver modelos corriendo:

```bash
ollama ps
```

Liberar modelo de memoria:

```bash
ollama stop <nombre>
```
