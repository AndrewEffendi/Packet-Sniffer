let modal; // Modal element
let packetData = []; // Store packet data
let sortDirection = {}; // Track sort direction for each column
let currentPage = 1;
let pageSize = 100;
let totalPages = 1;

// Fetch packet data and render table
function fetchPackets() {
    fetch('/packets')
        .then(response => response.json())
        .then(data => {
            packetData = data.packets; // Store packet data globally
            packetDetail = data.details; // Store packet detail globally
            threatLog = data.threats; // store the threat log globally
            renderTable(packetData, packetDetail); // Render table with fetched data
            renderThreatLog(threatLog);
        });
}

// Render table with sorted packet data
function renderThreatLog(threatLog) {
    const threatLogDiv = document.getElementById('threatLog');
    if (threatLog.length > 0) {
        threatLogDiv.innerHTML = ''; // Clear previous entries if threats exist
        threatLog.forEach((threat) => {
            threatLogDiv.innerHTML = threatLogDiv.innerHTML + threat + '<br>'; // set threat log
        });
    } else { 
        threatLogDiv.innerHTML = 'None';
    }
}

// Render table with sorted packet data
function renderTable(data, detail) {
    const table = document.getElementById('packetsTable');
    const tbody = table.querySelector('tbody') || table.createTBody();
    tbody.innerHTML = '';  // Clear previous entries

    // Calculate pagination
    totalPages = Math.ceil(data.length / pageSize);
    const startIndex = (currentPage - 1) * pageSize;
    const endIndex = Math.min(startIndex + pageSize, data.length);

    // Update page selector and info
    updatePageSelector();
    document.getElementById('totalPackets').textContent = 
        `Total: ${data.length} packets (${totalPages} pages)`;
    
    // Update pagination buttons
    document.getElementById('prevPage').disabled = currentPage === 1;
    document.getElementById('nextPage').disabled = currentPage === totalPages;

    // Get current page's data
    const pageData = data.slice(startIndex, endIndex);
    const pageDetail = detail.slice(startIndex, endIndex);

    // Add packet data to the table
    pageData.forEach((packet, index) => {
        const row = tbody.insertRow();
        const absoluteIndex = startIndex + index;
        
        let protocolClass = 'other';
        if (packet.protocol_type) {
            protocolClass = packet.protocol_type.toLowerCase().trim();
        }
        row.className = `protocol-${protocolClass}`;
        
        row.innerHTML = `
            <td>${absoluteIndex + 1}</td>
            <td>${packet.elapsed_time}</td>
            <td>${packet.source}</td>
            <td>${packet.destination}</td>
            <td>${packet.protocol_name || 'N/A'}</td>
        `;

        // Add click event listener to the row
        row.addEventListener('click', () => {
            if (pageDetail[index]) {
                showPacketDetails(pageDetail[index]);
            } else {
                console.error("No details found for packet at index:", absoluteIndex);
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

    renderTable(packetData, packetDetail);
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
    const dstIp = document.getElementById('dst_ip').value;
    const pcapFilename = document.getElementById('pcap_filename').value;
    const selectedPacketTypes = [];
    if (document.getElementById('icmp').checked) selectedPacketTypes.push("icmp");
    if (document.getElementById('tcp').checked) selectedPacketTypes.push("tcp");
    if (document.getElementById('udp').checked) selectedPacketTypes.push("udp");
    if (document.getElementById('arp').checked) selectedPacketTypes.push("arp");

    try {
        // Reset pagination when starting new capture
        currentPage = 1;
        
        const response = await fetch('/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                src_ip: srcIp, 
                dst_ip: dstIp, 
                pcap_filename: pcapFilename, 
                packet_types: selectedPacketTypes 
            })
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

//pagination control
function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        renderTable(packetData, packetDetail);
    }
}

function nextPage() {
    if (currentPage < totalPages) {
        currentPage++;
        renderTable(packetData, packetDetail);
    }
}

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('pageSize').addEventListener('change', function(e) {
        pageSize = parseInt(e.target.value);
        currentPage = 1;  // Reset to first page
        renderTable(packetData, packetDetail);
    });
});

function updatePageSelector() {
    const pageSelect = document.getElementById('pageSelect');
    pageSelect.innerHTML = '';
    
    for (let i = 1; i <= totalPages; i++) {
        const option = document.createElement('option');
        option.value = i;
        option.text = `Page ${i} of ${totalPages}`;
        option.selected = i === currentPage;
        pageSelect.appendChild(option);
    }
}

// go to specific page
function goToPage(page) {
    currentPage = parseInt(page);
    renderTable(packetData, packetDetail);
}
