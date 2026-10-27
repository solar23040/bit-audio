package com.solar23040.bitaudio.ui.screens

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.solar23040.bitaudio.AppGraph
import com.solar23040.bitaudio.ui.components.openAppSettings
import kotlin.math.roundToInt

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    graph: AppGraph,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val settings by graph.settings.settings.collectAsStateWithLifecycle()
    val fingerprint by graph.runtime.identityFingerprint.collectAsStateWithLifecycle()
    var nameInput by remember(settings.displayName) { mutableStateOf(settings.displayName) }
    var ttl by remember(settings.defaultTtl) { mutableFloatStateOf(settings.defaultTtl.toFloat()) }
    var showRotateConfirm by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            SettingsSection(title = "Profile") {
                OutlinedTextField(
                    value = nameInput,
                    onValueChange = { nameInput = it.take(32) },
                    label = { Text("Display name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { graph.setNickname(nameInput) },
                        enabled = nameInput.isNotBlank() && nameInput != settings.displayName,
                    ) {
                        Text("Save")
                    }
                    Text(
                        text = "Shown as nickname#fingerprint to nearby phones.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.align(Alignment.CenterVertically),
                    )
                }
            }

            HorizontalDivider()

            SettingsSection(title = "Mesh") {
                Text(
                    text = "Default TTL: ${ttl.roundToInt()} hop" +
                        if (ttl.roundToInt() == 1) "" else "s",
                    style = MaterialTheme.typography.titleSmall,
                )
                Slider(
                    value = ttl,
                    onValueChange = { ttl = it },
                    valueRange = 1f..10f,
                    steps = 8,
                    onValueChangeFinished = {
                        graph.settings.setDefaultTtl(ttl.roundToInt())
                    },
                )
                Text(
                    text = "Higher TTL reaches further but spends more radio airtime.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                Spacer(Modifier.height(8.dp))
                Text("Retention", style = MaterialTheme.typography.titleSmall)
                Row(
                    modifier = Modifier.horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    listOf(24 to "24 hours", 72 to "3 days", 168 to "7 days").forEach { (hours, label) ->
                        FilterChip(
                            selected = settings.retentionHours == hours,
                            onClick = { graph.settings.setRetentionHours(hours) },
                            label = { Text(label) },
                        )
                    }
                }
                Text(
                    text = "Undelivered notes older than this are removed when the app starts. " +
                        "Delivered notes stay until you delete the channel.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Discoverable nearby", style = MaterialTheme.typography.titleSmall)
                        Text(
                            text = "Announce your nickname and fingerprint on the public " +
                                "nearby channel. You still hear others when this is off.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = settings.discoverable,
                        onCheckedChange = { graph.setDiscoverable(it) },
                    )
                }

                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Scan duty cycle", style = MaterialTheme.typography.titleSmall)
                        Text(
                            text = "Scan 10s, rest 20s while the mesh service runs. " +
                                "Applies the next time the service starts.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = settings.dutyCycleEnabled,
                        onCheckedChange = { graph.settings.setDutyCycleEnabled(it) },
                    )
                }
            }

            HorizontalDivider()

            SettingsSection(title = "Identity") {
                Text(
                    text = "Fingerprint",
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(
                    text = fingerprint.ifBlank { "Not loaded yet" },
                    style = MaterialTheme.typography.headlineSmall,
                    fontFamily = FontFamily.Monospace,
                )
                Text(
                    text = "Nearby peers see you as ${settings.displayName}#" +
                        fingerprint.ifBlank { "------" } +
                        ". This is SHA-256 of your Ed25519 public key, not a secret.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedButton(onClick = { showRotateConfirm = true }) {
                    Text("Rotate identity")
                }
                Text(
                    text = "Rotating creates a new key and fingerprint. Existing notes stay " +
                        "playable, but peers see you as a new phone.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            HorizontalDivider()

            SettingsSection(title = "Permissions") {
                Text(
                    text = "Microphone, Bluetooth, and notifications are requested in " +
                        "context. If a prompt was dismissed permanently, grant access in " +
                        "Android settings.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedButton(onClick = { openAppSettings(context) }) {
                    Text("Open app settings")
                }
            }

            HorizontalDivider()

            SettingsSection(title = "About") {
                Text("Bit Audio 0.1.0", style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = "Push-to-talk over a BLE mesh. No servers, no accounts. Nearby " +
                        "clips are public and signed; private channels use a shared QR key.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }

    if (showRotateConfirm) {
        AlertDialog(
            onDismissRequest = { showRotateConfirm = false },
            title = { Text("Rotate identity?") },
            text = {
                Text(
                    "A new Ed25519 key and fingerprint will be generated. Your nickname, " +
                        "channels and notes stay on this phone, but nearby peers see you " +
                        "as a new device.",
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        graph.rotateIdentity()
                        showRotateConfirm = false
                    },
                ) {
                    Text("Rotate")
                }
            },
            dismissButton = {
                TextButton(onClick = { showRotateConfirm = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun SettingsSection(
    title: String,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.primary,
        )
        content()
    }
}
