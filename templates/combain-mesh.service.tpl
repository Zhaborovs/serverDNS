[Unit]
Description=Combain-Mesh P2P Control Plane & Subscription API
After=network-online.target wg-quick@wg-mesh0.service docker.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${PROJECT_ROOT}
EnvironmentFile=-${STATE_DIR}/state.env
ExecStart=/usr/bin/python3 ${PROJECT_ROOT}/scripts/mesh/combain_mesh.py daemon --state-dir ${STATE_DIR} --port ${MESH_API_PORT}
Restart=always
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
