// Protocol Chart initialization
let protocolChart = null;
// Function to update protocol chart    
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

// Top Talkers Table update
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

// Throughput Line Chart initialization
let throughputChart = null;
let chart_interval = 100;

// Function to fetch throughput data from the server
function UpdatethroughputChart() {
    fetch('/Update_line_chart')  // Adjust the endpoint as necessary
        .then(response => response.json())
        .then(data => {
            const throughput_data = data.throughput_data; 
            const timestamps = data.timestamp; 
            
            if (throughput_data === 'not_sniffing') {
                return;
            }

            if (throughput_data.length !== timestamps.length) {
                throw new Error("Throughput Chart: two arrays do not have the same length");
            } else if (throughput_data.length !== chart_interval) {
                throw new Error("Throughput Chart: array length is not equal to chart interval");
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
                        label: 'Throughput (Bytes)',
                        data: throughput_data, 
                        borderColor: '#2c3e50',
                        borderWidth: 2,
                        fill: false,
                        pointRadius: 0,
                        lineTension: 0.1
                    }]
                },
                options: {
                    animation: false, // Disable animations
                    maintainAspectRatio: false,
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
                            },
                            ticks:{
                                maxRotation: 60,
                                minRotation: 0,
                                autosikip: true
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
            
            // Hide the chart if there is no data
            if (throughput_data.every(value => value === null)) {
                ctx.canvas.style.display = 'none'; // Hide the chart canvas
            } else {
                ctx.canvas.style.display = 'block'; // Show the chart canvas
            }
        })
        .catch(error => {
            console.error('Error fetching throughput data:', error);
        });
}

// Start updating the charts when the page loads
document.addEventListener('DOMContentLoaded', function() {
    // Update protocol chart every second
    setInterval(updateProtocolChart, 1000);
    
    // Update top talkers every second
    setInterval(updateTopTalkers, 1000);

    // Update thoughput line chart every second
    setInterval(UpdatethroughputChart, 1000);
});




