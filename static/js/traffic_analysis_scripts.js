const socket = io(); // Initialize socket connection
socket.on('message', (data) => {
    console.log(data.data); // Log when the socket is connected
});

// Protocol Chart initialization
let protocolChart = null;

function updateProtocolChart() {
    fetch('/protocol-stats')
        .then(response => response.json())
        .then(data => {
            // Update total packets count
            document.getElementById('total-packets').textContent = data.total_packets;
            
            const ctx = document.getElementById('protocolChart').getContext('2d');
            
            // Define protocol order (Other will be automatically last)
            const protocolOrder = ['ARP', 'ICMP', 'TCP', 'UDP'];
            
            // Sort the data according to protocol order
            const sortedLabels = Object.keys(data.counts).sort((a, b) => {
                if (a === 'Other') return 1;  // Other always goes last
                if (b === 'Other') return -1;
                return protocolOrder.indexOf(a) - protocolOrder.indexOf(b);
            });
            
            // Get corresponding values in the same order
            const sortedPercentages = sortedLabels.map(label => data.percentages[label]);
            
            // Destroy existing chart if it exists
            if (protocolChart) {
                protocolChart.destroy();
            }
            
            // Create new chart
            protocolChart = new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: sortedLabels,
                    datasets: [{
                        data: sortedPercentages,
                        backgroundColor: [
                            '#FF6384',   // ARP
                            '#36A2EB',   // ICMP
                            '#FFCE56',   // TCP
                            '#4BC0C0',   // UDP
                            '#9966FF'    // Other
                        ]
                    }]
                },
                options: {
                    animation: {
                        duration: 0
                    },
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Protocol Distribution'
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.raw.toFixed(1);
                                    const count = data.counts[label];
                                    return `${label}: ${value}% (${count} packets)`;
                                }
                            }
                        }
                    }
                }
            });
        });
}

function updateTopTalkers() {
    fetch('/top-talkers')
        .then(response => response.json())
        .then(data => {
            // Update senders table
            const sendersBody = document.getElementById('top-senders-body');
            sendersBody.innerHTML = data.top_senders.map((item, index) => `
                <tr>
                    <td>${index + 1}</td>
                    <td>${item.ip}</td>
                    <td>${item.formatted_bytes}</td>
                    <td>${item.packets}</td>
                </tr>
            `).join('');

            // Update receivers table
            const receiversBody = document.getElementById('top-receivers-body');
            receiversBody.innerHTML = data.top_receivers.map((item, index) => `
                <tr>
                    <td>${index + 1}</td>
                    <td>${item.ip}</td>
                    <td>${item.formatted_bytes}</td>
                    <td>${item.packets}</td>
                </tr>
            `).join('');
        });
}

// Start updating the charts when the page loads
document.addEventListener('DOMContentLoaded', function() {
    // Update protocol chart every second
    setInterval(updateProtocolChart, 1000);
    
    // Update top talkers every second
    setInterval(updateTopTalkers, 1000);
});

// Throughput Line Chart initialization
let chart_interval = 100;
let throughputChart = null;
let throughputData = new Array(chart_interval).fill(null); // Pre-fill with null for chart_interval seconds
let timestamps = Array.from({ length: chart_interval }, (_, i) => i);
let totalSeconds = 0; // Latest seconds

// Monitor the update
socket.on('throughput_update', (data) => {
    const currentThroughput = data.throughput;

    // Update the new data in the chart
    if (totalSeconds < chart_interval) {
        throughputData[totalSeconds] = currentThroughput; // Update the current second
    } else {
        // Shift the data to the left if we exceed chart_interval seconds
        throughputData.shift(); // Remove the oldest data point
        throughputData.push(currentThroughput); // Add the new data point
    }

    // Update chart
    const ctx = document.getElementById('throughputChart').getContext('2d');

    // Destroy existing chart if it exists
    if (throughputChart) {
        throughputChart.destroy();
    }

    // Create new chart
    throughputChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timestamps, 
            datasets: [{
                label: 'Throughput (Bytes/s)',
                data: throughputData, 
                borderColor: '#2c3e50',
                borderWidth: 2,
                fill: false,
                pointRadius: 0,
                lineTension: 0.1
            }]
        },
        options: {
            animation: false, // Disable animations
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: '#e0e0e0'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Time (seconds)'
                    },
                    grid: {
                        color: '#e0e0e0'
                    }
                }
            },
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Real-time Network Throughput per Second'
                },
                tooltip: {
                    backgroundColor: '#ffffff',
                    titleColor: '#2c3e50',
                    bodyColor: '#2c3e50'
                }
            }
        }
    });

    totalSeconds++;
    
    // Hide the chart if there is no data
    if (throughputData.every(value => value === null)) {
        ctx.canvas.style.display = 'none'; // Hide the chart canvas
    } else {
        ctx.canvas.style.display = 'block'; // Show the chart canvas
    }
});



