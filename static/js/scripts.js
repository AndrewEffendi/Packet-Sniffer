let modal; // Modal element
let packetData = []; // Store packet data
let sortDirection = {}; // Track sort direction for each column

// Fetch packet data and render table
function fetchPackets() {
    fetch('/packets')
        .then(response => response.json())
        .then(data => {
            packetData = data.packets; // Store packet data globally
            packetDetail = data.details; // Store packet detail globally
            renderTable(packetData, packetDetail); // Render table with fetched data
        });
}

// Render table with sorted packet data
function renderTable(data, detail) {
    const table = document.getElementById('packetsTable');
    table.innerHTML = ''; // Clear previous entries

    // Create table headers with sorting enabled
    const headerRow = table.insertRow();
    headerRow.innerHTML = `
        <th onclick="sortTable('index')">No.</th>
        <th onclick="sortTable('elapsed_time')">Time</th>
        <th onclick="sortTable('source')">Source</th>
        <th onclick="sortTable('destination')">Destination</th>
        <th onclick="sortTable('protocol_name')">Protocol</th>
    `;

    // Add packet data to the table
    data.forEach((packet, index) => {
        const row = table.insertRow();
        row.innerHTML = `
            <td>${packet.index + 1}</td>
            <td>${packet.elapsed_time}</td>
            <td>${packet.source}</td>
            <td>${packet.destination}</td>
            <td>${packet.protocol_name || 'N/A'}</td>
        `;

        // Add click event listener to the row
        row.addEventListener('click', () => {
            if (detail && detail[index]) {
                showPacketDetails(detail[index]);
            } else {
                console.error("No details found for packet at index:", index);
            }
        });
    });
}

// Sort table data by the specified column
function sortTable(column) {
    sortDirection[column] = !sortDirection[column];

    packetData.sort((a, b) => {
        if (a[column] < b[column]) return sortDirection[column] ? -1 : 1;
        if (a[column] > b[column]) return sortDirection[column] ? 1 : -1;
        return 0;
    });

    renderTable(packetData);
}

// Show packet details in the modal
function showPacketDetails(details) {
    const modalContent = document.getElementById('modalContent');
    modalContent.innerHTML = details; // Set the modal content
    modal.style.display = "block"; // Show the modal
}

// Close the modal
function closeModal() {
    modal.style.display = "none";
}

// Initialize modal
window.onload = () => {
    modal = document.getElementById('myModal');

    document.getElementsByClassName("close")[0].onclick = closeModal;

    window.onclick = (event) => {
        if (event.target === modal) {
            closeModal();
        }
    };

    setInterval(fetchPackets, 1000); // Fetch every second
};

async function sendStartRequest() {
    const srcIp = document.getElementById('src_ip').value;
    const destIp = document.getElementById('dest_ip').value;
    const pcapFilename = document.getElementById('pcap_filename').value;
    const selectedPacketTypes = [];
    if (document.getElementById('icmp').checked) selectedPacketTypes.push("icmp");
    if (document.getElementById('tcp').checked) selectedPacketTypes.push("tcp");
    if (document.getElementById('udp').checked) selectedPacketTypes.push("udp");
    if (document.getElementById('arp').checked) selectedPacketTypes.push("arp");

    try {
        const response = await fetch('/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ src_ip: srcIp, dest_ip: destIp, pcap_filename: pcapFilename, packet_types: selectedPacketTypes })
        });
        const data = await response.json();
        alert(data.status);
    } catch (error) {
        alert('Error communicating with server: ' + error);
    }
}

async function sendStopRequest() {
    try {
        const response = await fetch('/stop', { method: 'POST' });
        const data = await response.json();
        alert(data.status);
    } catch (error) {
        alert('Error communicating with server: ' + error);
    }
}

function toggleAllCheckboxes(selectAllCheckbox) {
    const checkboxes = document.querySelectorAll('input[name="packet_type"]');
    checkboxes.forEach(checkbox => {
        checkbox.checked = selectAllCheckbox.checked;
    });
}
