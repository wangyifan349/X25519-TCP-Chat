# pip install -U sentence-transformers faiss-cpu torch numpy
"""
This file implements a multilingual FAQ retrieval system using sentence-transformers/paraphrase-multilingual-mpnet-base-v2 and FAISS. It defines a structured medical knowledge base in which multiple semantically related questions map to a single authoritative answer, with the content focused on core biomedical mechanisms such as neuraminidase inhibitors, influenza antivirals, antibiotics, antipyretics, and related pharmacological principles. The script encodes all predefined questions into normalized sentence embeddings, builds a FAISS inner-product index for efficient semantic search, and then accepts user queries in an interactive loop. For each query, it retrieves the most relevant matched questions, deduplicates results at the answer level, and prints the corresponding medical explanation while preserving multi-line formatting and indentation. This design is suitable for building a lightweight, mechanism-oriented medical QA demo that emphasizes conceptual accuracy, retrieval efficiency, and clear answer presentation.
"""
import faiss
import numpy as np
import textwrap
from sentence_transformers import SentenceTransformer


faq_data = [
    {
        "answer": textwrap.dedent("""
            奥司他韦属于流感抗病毒药中的神经氨酸酶抑制剂。

            从药物化学角度看，奥司他韦本身是前药。进入体内后，它需要经过酯水解，转化为真正发挥作用的活性代谢物。
            这个活性代谢物的靶点，是流感病毒包膜表面的神经氨酸酶。

            在流感病毒复制周期中，宿主细胞表面和黏液层中存在唾液酸残基。流感病毒复制完成后，新生成的病毒颗粒如果仍然被这些唾液酸残基“黏住”，就不容易从感染细胞表面脱离，也不容易继续扩散。
            神经氨酸酶的作用，就是切断这些末端唾液酸残基，帮助新生病毒颗粒从宿主细胞表面释放出来。

            奥司他韦抑制神经氨酸酶后，会产生两个直接后果：
                1. 新生成的病毒颗粒更难从感染细胞表面脱离
                2. 病毒颗粒之间更容易发生聚集，进一步降低扩散效率

            因此，奥司他韦的本质不是“直接把病毒杀死”，而是阻断流感病毒复制周期中“释放和播散”这一步，从而降低病毒在呼吸道上皮中的继续扩展能力。
        """).strip(),
        "questions": [
            "奥司他韦是什么药理机制",
            "奥司他韦为什么能抗流感",
            "奥司他韦是怎么起作用的",
            "奥司他韦为什么属于神经氨酸酶抑制剂",
            "达菲的作用原理是什么",
        ],
    },

    {
        "answer": textwrap.dedent("""
            神经氨酸酶抑制剂是一类专门针对流感病毒释放阶段的抗病毒药物。

            流感病毒包膜上最重要的两类表面蛋白，可以概括为：
                - 血凝素：负责与宿主细胞表面的唾液酸结合
                - 神经氨酸酶：负责切断唾液酸，促进病毒脱离和扩散

            也就是说，血凝素偏向“黏上去”，神经氨酸酶偏向“放开来”。
            这两个过程共同决定了病毒能否顺利完成感染和传播。

            神经氨酸酶抑制剂的代表药物包括：
                - 奥司他韦
                - 扎那米韦
                - 帕拉米韦

            这一类药物的共同机制不是抑制病毒进入宿主细胞，也不是抑制病毒蛋白翻译，而是抑制神经氨酸酶催化的唾液酸切割步骤。
            因此，它们主要作用在病毒生命周期的后段，即新生病毒颗粒的释放与局部扩散阶段。

            所以，神经氨酸酶抑制剂的医学本质可以概括为：
            “不是阻止病毒附着，而是阻止病毒高效脱离与播散。”
        """).strip(),
        "questions": [
            "什么是神经氨酸酶抑制剂",
            "神经氨酸酶抑制剂的机制是什么",
            "神经氨酸酶在流感病毒中起什么作用",
            "奥司他韦这类药为什么能抑制病毒释放",
            "流感病毒为什么要靠神经氨酸酶扩散",
        ],
    },

    {
        "answer": textwrap.dedent("""
            流感抗病毒药并不只有一种机制。

            目前常见的两条主要机制路线是：

                第一类：神经氨酸酶抑制剂
                    代表药物包括奥司他韦、扎那米韦、帕拉米韦
                    这类药物主要抑制病毒颗粒从感染细胞表面释放

                第二类：帽依赖性内切酶抑制剂
                    代表药物是巴洛沙韦
                    这类药物作用于流感病毒 RNA 聚合酶复合体相关过程，干扰病毒 RNA 转录

            从分子层面看，巴洛沙韦和奥司他韦的差异很大：
                - 奥司他韦主要影响病毒“放出来”这一步
                - 巴洛沙韦主要影响病毒“把遗传信息抄出来”这一步

            因此，两者都属于流感抗病毒药，但靶点不同、作用阶段不同。
            一个更偏向复制周期后段的释放阶段，一个更偏向复制周期中前段的转录阶段。

            如果从药理学思维理解，这也是抗病毒药设计的典型逻辑：
            不是笼统“抗病毒”，而是围绕病毒生命周期中的关键酶、关键复合体、关键复制步骤，寻找可抑制的分子靶点。
        """).strip(),
        "questions": [
            "流感抗病毒药有哪些机制",
            "奥司他韦和巴洛沙韦机制有什么不同",
            "巴洛沙韦是怎么起作用的",
            "流感抗病毒药为什么分不同类型",
            "抗流感药物的分子机制有哪些",
        ],
    },

    {
        "answer": textwrap.dedent("""
            抗病毒药和抗生素的根本区别，在于它们针对的生物学对象完全不同。

            病毒不是完整细胞，没有自己的细胞壁、核糖体和独立代谢系统。
            它必须进入宿主细胞，借用宿主细胞的复制、转录和翻译体系来完成增殖。
            因此，抗病毒药往往设计成针对病毒特有的酶、离子通道、聚合酶复合体或病毒生命周期中的关键步骤。

            细菌则是完整的原核细胞，具有：
                - 细胞壁
                - 核糖体
                - 独立代谢通路
                - 自主分裂能力

            因此，抗生素常见的作用靶点包括：
                - 细胞壁合成
                - 蛋白质合成
                - 核酸合成
                - 叶酸代谢等

            这就是为什么抗生素不能治疗流感：
                - 流感是病毒感染
                - 抗生素针对的是细菌靶点
                - 流感病毒本身没有可供抗生素攻击的细胞壁和细菌核糖体

            所以，抗病毒药与抗生素并不是“不同名字但差不多”的药，而是建立在两套完全不同微生物学基础上的治疗体系。
        """).strip(),
        "questions": [
            "抗病毒药和抗生素的本质区别是什么",
            "为什么抗生素不能治疗流感",
            "病毒感染和细菌感染用药原理有什么不同",
            "抗病毒药和抗菌药靶点为什么不同",
            "流感为什么不用抗生素治疗本体",
        ],
    },

    {
        "answer": textwrap.dedent("""
            头孢菌素属于β-内酰胺类抗生素，其核心药理基础是抑制细菌细胞壁合成。

            细菌细胞壁的主要骨架是肽聚糖。肽聚糖不是一层简单外壳，而是由多糖链和肽链交联形成的高强度网状结构。
            对细菌来说，肽聚糖决定了：
                - 细胞形态是否稳定
                - 渗透压下能否不裂解
                - 分裂过程中细胞壁能否正确重建

            β-内酰胺类抗生素的关键靶点，是细菌细胞壁合成所需的一组酶，也就是青霉素结合蛋白。
            当这些酶被抑制后，肽聚糖交联受阻，细胞壁机械强度下降，细菌在生长和分裂过程中更容易发生破裂，因此这类药通常表现为杀菌作用。

            头孢分代，本质上不是“越新越高级”，而是不同代际在抗菌谱和对某些细菌的稳定性上存在差异。
            它反映的是分子结构变化后，对不同细菌外膜通透性、酶稳定性、以及与靶酶结合特征的变化，而不是一个线性的“强弱排序”。

            因此，从机制上理解头孢，最重要的不是记代数本身，而是记住三点：
                - 它属于β-内酰胺类
                - 它的核心靶点是细胞壁合成相关酶
                - 它通过破坏肽聚糖网状结构的建立来实现杀菌
        """).strip(),
        "questions": [
            "头孢的作用机制是什么",
            "β内酰胺类抗生素为什么能杀菌",
            "头孢为什么作用于细胞壁",
            "头孢分代的本质是什么",
            "青霉素结合蛋白是什么",
        ],
    },

    {
        "answer": textwrap.dedent("""
            β-内酰胺类抗生素的一个经典耐药机制，是细菌产生β-内酰胺酶。

            这类酶的化学本质，是能够水解β-内酰胺环。
            而β-内酰胺环正是这类抗生素分子实现活性的核心结构之一。
            一旦这个环被打开，药物分子的关键构象被破坏，就难以再有效结合细胞壁合成相关靶酶，抗菌活性就会明显下降甚至消失。

            所以，β-内酰胺酶耐药不是“细菌变硬了”或者“细菌适应了药”，而是一个非常具体的化学失活过程：
                - 细菌表达酶
                - 酶切开β-内酰胺环
                - 药物失去对靶酶的有效抑制能力

            这也是为什么会出现β-内酰胺酶抑制剂这类配伍思路。
            其核心逻辑不是额外杀菌，而是优先占据、抑制或牵制这些灭活酶，从而保护真正负责抗菌的β-内酰胺抗生素分子。
        """).strip(),
        "questions": [
            "什么是β内酰胺酶",
            "细菌为什么会对头孢耐药",
            "β内酰胺环为什么重要",
            "β内酰胺酶是怎么让抗生素失效的",
            "抗生素耐药的化学原理是什么",
        ],
    },

    {
        "answer": textwrap.dedent("""
            退烧药之所以能退热，核心与前列腺素尤其是前列腺素相关通路有关。

            发热并不只是“身体变热了”，而是体温调定点发生了上移。
            当机体受到感染或炎症刺激时，致热性信号会推动中枢体温调节系统进入更高设定值，于是机体通过寒战、外周血管收缩等方式把体温抬高到新的水平。

            常见退烧药的共同点，是减少促使体温调定点上移的前列腺素信号。
            一旦这条信号减弱，体温调定点下移，机体就更容易通过散热把体温降下来。

            所以，退烧药不是单纯“把热量压下去”，而是通过改变炎症介质与中枢体温调控之间的信号联系，重设体温调节状态。
            从病理生理角度看，这比“物理降温”更接近药物退热的本质。
        """).strip(),
        "questions": [
            "退烧药为什么能退烧",
            "发热的生理机制是什么",
            "体温为什么会升高",
            "退热和前列腺素有什么关系",
            "发烧时为什么吃药体温会降下来",
        ],
    },

    {
        "answer": textwrap.dedent("""
            对乙酰氨基酚是一种退热镇痛药，但它与典型非甾体抗炎药并不完全相同。

            目前公认的一点是：
            它的退热和镇痛作用主要与中枢机制有关，但其精确分子机制尚未被完全阐明。
            也就是说，它确实有效，但在药理学上，它不像布洛芬那样可以被非常简洁地概括为“外周环氧合酶抑制剂”。

            从代谢角度看，对乙酰氨基酚的大部分会经过结合代谢后排出；
            但其中有一小部分会经过氧化代谢，形成一种活性较强、具有肝毒性的反应性中间体。
            正常情况下，这个中间体会被谷胱甘肽清除。
            如果这一代谢负荷过大，或者谷胱甘肽储备不足，这个中间体就会与肝细胞内蛋白发生共价结合，进而造成肝细胞损伤。

            因此，对乙酰氨基酚在药理学上很有代表性：
                - 作用机制偏中枢
                - 抗炎作用相对弱于典型非甾体抗炎药
                - 代谢毒理学意义非常强，尤其体现为反应性代谢产物与肝损伤之间的关系
        """).strip(),
        "questions": [
            "对乙酰氨基酚的作用机制是什么",
            "对乙酰氨基酚为什么能退烧",
            "对乙酰氨基酚和布洛芬机制有什么不同",
            "对乙酰氨基酚为什么会伤肝",
            "对乙酰氨基酚的代谢原理是什么",
        ],
    },

    {
        "answer": textwrap.dedent("""
            布洛芬属于非甾体抗炎药，其核心机制是可逆抑制环氧合酶，从而减少前列腺素以及相关类花生酸介质的生成。

            环氧合酶位于花生四烯酸代谢通路中，是把花生四烯酸转化为前列腺素前体的重要酶。
            当前列腺素生成减少后，会出现三类主要药理效应：

                1. 退热
                    因为与体温调定点上移相关的前列腺素信号下降

                2. 镇痛
                    因为前列腺素减少后，外周伤害感受器的敏化程度下降

                3. 抗炎
                    因为炎症局部多种前列腺素介导的血管扩张、渗出和疼痛放大效应减弱

            因此，布洛芬和对乙酰氨基酚虽然都能退热镇痛，但它们的药理重心不同：
                - 布洛芬更典型地体现“环氧合酶—前列腺素”这条抗炎通路
                - 对乙酰氨基酚则更偏向中枢退热镇痛机制

            从基础药理学上看，布洛芬是理解“前列腺素为什么会同时影响疼痛、炎症和发热”的一个非常典型的代表药。
        """).strip(),
        "questions": [
            "布洛芬的作用机制是什么",
            "布洛芬为什么既能退烧又能止痛",
            "布洛芬为什么属于非甾体抗炎药",
            "环氧合酶和前列腺素是什么关系",
            "布洛芬和前列腺素有什么联系",
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
    question = input("\n请输入问题（输入 q / quit / exit 退出）：").strip()
    if not question:
        print("问题不能为空")
        continue
    if question.lower() in {"q", "quit", "exit"}:
        print("已退出")
        break
    results = search_faq(
        question,
        top_k=3,
        fetch_k=20,
        score_threshold=0.35,
    )
    if not results:
        print("没有找到足够可信的答案")
        continue
    print("\n检索结果：")
    for i, item in enumerate(results, start=1):
        print("-" * 60)
        print(f"Top {i}")
        print("输入问题:", item["query"])
        print("匹配问题:", item["matched_question"])
        print("分数    :", round(item["score"], 4))
        print("答案    :")
        print(item["answer"])   # 这里会保留换行和缩进
