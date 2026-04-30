# pip install -U sentence-transformers faiss-cpu torch numpy
"""
This file implements a multilingual FAQ retrieval system using
sentence-transformers/paraphrase-multilingual-mpnet-base-v2 and FAISS.

It defines a structured medical knowledge base where multiple semantically
related questions map to a single authoritative answer. The content focuses
on core biomedical mechanisms such as neuraminidase inhibitors, influenza
antivirals, antibiotics, antipyretics, and related pharmacological principles.

The script encodes all predefined questions into normalized sentence embeddings,
builds a FAISS inner-product index for efficient semantic search, and then
accepts user queries in an interactive loop.

For each query, it retrieves the most relevant matched questions, deduplicates
results at the answer level, and prints the corresponding medical explanation
while preserving multi-line formatting and indentation.

This design is suitable for building a lightweight, mechanism-oriented medical
QA demo that emphasizes conceptual accuracy, retrieval efficiency, and clear
answer presentation.
"""
import faiss
import numpy as np
import textwrap
from sentence_transformers import SentenceTransformer


faq_data = [
    {
        "answer": textwrap.dedent("""
            Oseltamivir belongs to the class of influenza antivirals known as neuraminidase inhibitors.

            From a medicinal chemistry perspective, oseltamivir itself is a prodrug.
            After entering the body, it undergoes ester hydrolysis and is converted into
            its active metabolite.

            This active metabolite targets neuraminidase on the surface of the influenza virus.

            During the viral replication cycle, sialic acid residues are present on the
            host cell surface and in mucus. After replication, newly formed viral particles
            may remain attached to these residues, making it difficult for them to detach
            and spread.

            Neuraminidase cleaves these terminal sialic acid residues, allowing newly
            formed viral particles to be released from the host cell surface.

            By inhibiting neuraminidase, oseltamivir leads to two direct consequences:
                1. Newly formed viral particles have more difficulty detaching
                2. Viral particles are more likely to aggregate, reducing spread efficiency

            Therefore, oseltamivir does not directly "kill" the virus, but rather blocks
            the release and spread stage of the viral replication cycle.
        """).strip(),
        "questions": [
            "What is the mechanism of oseltamivir",
            "Why does oseltamivir work against influenza",
            "How does oseltamivir work",
            "Why is oseltamivir a neuraminidase inhibitor",
            "What is the mechanism of Tamiflu",
        ],
    },

    {
        "answer": textwrap.dedent("""
            Neuraminidase inhibitors are antiviral drugs that specifically target
            the viral release stage of influenza.

            The influenza virus has two key surface proteins:
                - Hemagglutinin: binds to sialic acid on host cells
                - Neuraminidase: cleaves sialic acid to promote release and spread

            Hemagglutinin enables attachment, while neuraminidase enables release.

            Representative drugs include:
                - Oseltamivir
                - Zanamivir
                - Peramivir

            These drugs do not prevent viral entry or protein synthesis,
            but instead inhibit the neuraminidase-mediated cleavage of sialic acid.

            Therefore, they act at the late stage of the viral lifecycle,
            specifically during viral release and local spread.

            In essence:
            "They do not prevent attachment, but prevent efficient release and dissemination."
        """).strip(),
        "questions": [
            "What are neuraminidase inhibitors",
            "Mechanism of neuraminidase inhibitors",
            "Role of neuraminidase in influenza",
            "Why do these drugs inhibit viral release",
            "Why influenza needs neuraminidase to spread",
        ],
    },

    {
        "answer": textwrap.dedent("""
            Influenza antivirals do not all share the same mechanism.

            Two major classes are:

                1. Neuraminidase inhibitors
                   (oseltamivir, zanamivir, peramivir)
                   → inhibit viral release

                2. Cap-dependent endonuclease inhibitors
                   (baloxavir)
                   → inhibit viral RNA transcription

            At the molecular level:
                - Oseltamivir affects viral release
                - Baloxavir affects viral transcription

            Both are antivirals, but act at different stages.

            This reflects a core principle of antiviral drug design:
            targeting key enzymes and processes within the viral lifecycle.
        """).strip(),
        "questions": [
            "Mechanisms of influenza antivirals",
            "Difference between oseltamivir and baloxavir",
            "How baloxavir works",
            "Why antivirals have different types",
            "Molecular mechanisms of flu drugs",
        ],
    },

    {
        "answer": textwrap.dedent("""
            The fundamental difference between antivirals and antibiotics lies in
            their biological targets.

            Viruses are not complete cells. They lack cell walls, ribosomes,
            and independent metabolic systems. They must rely on host cells.

            Therefore, antivirals target:
                - Viral enzymes
                - Ion channels
                - Polymerase complexes
                - Key lifecycle steps

            Bacteria, however, are full prokaryotic cells with:
                - Cell walls
                - Ribosomes
                - Independent metabolism
                - Self-replication

            Antibiotics target:
                - Cell wall synthesis
                - Protein synthesis
                - Nucleic acid synthesis
                - Folate metabolism

            This is why antibiotics cannot treat influenza:
                - Influenza is viral
                - Antibiotics target bacterial structures
        """).strip(),
        "questions": [
            "Difference between antivirals and antibiotics",
            "Why antibiotics don't work for flu",
            "Virus vs bacteria drug mechanisms",
            "Why targets differ",
            "Why flu isn't treated with antibiotics",
        ],
    },
]

MODEL_NAME = "sentence-transformers/paraphrase-multilingual-mpnet-base-v2"
model = SentenceTransformer(MODEL_NAME)

questions = []
answer_ids = []
answers = []

for answer_id, item in enumerate(faq_data):
    answers.append(item["answer"])
    for q in item["questions"]:
        questions.append(q)
        answer_ids.append(answer_id)

question_embeddings = model.encode(
    questions,
    batch_size=32,
    convert_to_numpy=True,
    normalize_embeddings=True,
    show_progress_bar=True,
)

question_embeddings = question_embeddings.astype("float32")
dim = question_embeddings.shape[1]

index = faiss.IndexFlatIP(dim)
index.add(question_embeddings)


def search_faq(query, top_k=3, fetch_k=20, score_threshold=None):
    query_vec = model.encode(
        [query],
        convert_to_numpy=True,
        normalize_embeddings=True,
    ).astype("float32")

    fetch_k = min(fetch_k, len(questions))
    scores, indices = index.search(query_vec, fetch_k)

    results = []
    seen_answer_ids = set()

    for score, idx in zip(scores[0], indices[0]):
        if idx == -1:
            continue

        answer_id = answer_ids[idx]

        if answer_id in seen_answer_ids:
            continue

        if score_threshold is not None and float(score) < score_threshold:
            continue

        seen_answer_ids.add(answer_id)

        results.append(
            {
                "query": query,
                "matched_question": questions[idx],
                "answer": answers[answer_id],
                "score": float(score),
                "answer_id": int(answer_id),
            }
        )

        if len(results) >= top_k:
            break

    return results


while True:
    question = input("\nEnter your question (type q / quit / exit to exit): ").strip()
    if not question:
        print("Question cannot be empty")
        continue
    if question.lower() in {"q", "quit", "exit"}:
        print("Exited")
        break
    results = search_faq(
        question,
        top_k=3,
        fetch_k=20,
        score_threshold=0.35,
    )
    if not results:
        print("No sufficiently reliable answer found")
        continue
    print("\nSearch results:")
    for i, item in enumerate(results, start=1):
        print("-" * 60)
        print(f"Top {i}")
        print("Query           :", item["query"])
        print("Matched question:", item["matched_question"])
        print("Score           :", round(item["score"], 4))
        print("Answer          :")
        print(item["answer"])
