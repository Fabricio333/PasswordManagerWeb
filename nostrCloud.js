// NOSTRCLOUD.JS
window.addEventListener('DOMContentLoaded', () => {
    const {
        nip19, nip04, relayInit,
        getPublicKey, getEventHash, signEvent, utils
    } = window.NostrTools;

    const defaultRelays = [
        "wss://relay.damus.io",
        "wss://nostr-pub.wellorder.net",
        "wss://relay.snort.social",
        "wss://nos.lol"
    ];
    let relayList = [...defaultRelays];

    function updateRelayDisplay() {
        const list = document.getElementById("relayListDisplay");
        list.innerHTML = "";
        relayList.forEach((r, i) => {
            const li = document.createElement("li");
            li.textContent = r;
            const x = document.createElement("button");
            x.textContent = "❌";
            x.onclick = () => { relayList.splice(i, 1); updateRelayDisplay(); };
            li.appendChild(x);
            list.appendChild(li);
        });
    }

    window.addRelay = function () {
        const val = document.getElementById("relayInput").value.trim();
        if (val && !relayList.includes(val)) relayList.push(val);
        document.getElementById("relayInput").value = "";
        updateRelayDisplay();
    }

    function decodeNsec(nsec) {
        const decoded = nip19.decode(nsec);
        if (decoded.type !== "nsec") throw new Error("Not a valid nsec");
        return { sk: decoded.data, pk: getPublicKey(decoded.data) };
    }

    // 🔐 Generates a deterministic nsec key from entropy
    document.getElementById("generateBtn").onclick = async () => {
        const input = document.getElementById("entropyInput");
        let entropy = input.value.trim();
        if (!entropy) {
            const bytes = crypto.getRandomValues(new Uint8Array(32));
            entropy = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        }
        const utf8 = new TextEncoder().encode(entropy);
        const hash = await crypto.subtle.digest("SHA-256", utf8);
        const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
        const nsec = nip19.nsecEncode(hex);
        document.getElementById("privateKey").value = nsec;
        document.getElementById("generatedNsec").textContent = nsec;
    };

    document.getElementById("backupBtn").onclick = async () => {
        const nsec = document.getElementById("privateKey").value.trim();
        const data = document.getElementById("dataInput").value;
        if (!nsec || !data || relayList.length === 0) return alert("Missing fields");
        let sk, pk;
        try { ({ sk, pk } = decodeNsec(nsec)); } catch (e) { return alert("Invalid nsec"); }
        const content = await nip04.encrypt(sk, pk, data);
        const event = {
            kind: 4, pubkey: pk, created_at: Math.floor(Date.now()/1000),
            tags: [["p", pk]], content
        };
        event.id = getEventHash(event);
        event.sig = signEvent(event, sk);
        for (const url of relayList) {
            try {
                const relay = relayInit(url);
                await relay.connect();
                relay.publish(event);
                relay.close();
            } catch (e) { console.warn("Relay error", url, e); }
        }
        alert("✅ Backup complete");
    };

    document.getElementById("retrieveBtn").onclick = async () => {
        const nsec = document.getElementById("privateKey").value.trim();
        if (!nsec) return alert("Missing private key");
        let sk, pk;
        try { ({ sk, pk } = decodeNsec(nsec)); } catch (e) { return alert("Invalid key"); }
        document.getElementById("retrievedData").textContent = "Fetching…";
        for (const url of relayList) {
            try {
                const relay = relayInit(url);
                await relay.connect();
                const sub = relay.sub([{ kinds: [4], "#p": [pk] }]);
                sub.on("event", async (e) => {
                    const decrypted = await nip04.decrypt(sk, e.pubkey, e.content);
                    document.getElementById("retrievedData").textContent = decrypted;
                });
                sub.on("eose", () => { sub.unsub(); relay.close(); });
            } catch (e) { console.warn("Relay", url, "failed", e); }
        }
    };

    updateRelayDisplay();
});