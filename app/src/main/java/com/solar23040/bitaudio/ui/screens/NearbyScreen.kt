package com.solar23040.bitaudio.ui.screens

import android.Manifest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.outlined.GraphicEq
import androidx.compose.material.icons.outlined.NearMe
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.solar23040.bitaudio.AppGraph
import com.solar23040.bitaudio.data.NearbyFeedFilter
import com.solar23040.bitaudio.mesh.NearbyPeer
import com.solar23040.bitaudio.permissions.AppPermissions
import com.solar23040.bitaudio.service.MeshForegroundService
import com.solar23040.bitaudio.ui.components.PermissionCard
import com.solar23040.bitaudio.ui.components.TalkBar
import com.solar23040.bitaudio.ui.components.VoiceNoteCard
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Public nearby feed: live peers plus hold-to-talk clips anyone in range can
 * hear. Private channels live behind the second bottom tab.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NearbyScreen(
    graph: AppGraph,
    onOpenSettings: () -> Unit,
    bottomBar: @Composable () -> Unit = {},
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val peers by graph.runtime.nearbyPeers.collectAsStateWithLifecycle()
    val muted by graph.peerPrefs.muted.collectAsStateWithLifecycle()
    val blocked by graph.peerPrefs.blocked.collectAsStateWithLifecycle()
    val settings by graph.settings.settings.collectAsStateWithLifecycle()
    val fingerprint by graph.runtime.identityFingerprint.collectAsStateWithLifecycle()
    val nearbyChannelId by graph.nearbyChannelId.collectAsStateWithLifecycle()
    val notesFlow = remember(nearbyChannelId) { graph.notes.forChannel(nearbyChannelId) }
    val notes by notesFlow.collectAsStateWithLifecycle(initialValue = emptyList())

    val visiblePeers = remember(peers, blocked) {
        NearbyFeedFilter.visiblePeers(peers, blocked)
    }
    val visibleNotes = remember(notes, muted, blocked) {
        NearbyFeedFilter.visibleNotes(notes, muted, blocked)
    }

    val viewModel: ChannelViewModel = viewModel(
        key = "nearby",
        factory = viewModelFactory {
            initializer { ChannelViewModel(graph, nearbyChannelId, nearby = true) }
        },
    )
    val isRecording by viewModel.isRecording.collectAsStateWithLifecycle()
    val amplitude by viewModel.amplitude.collectAsStateWithLifecycle()
    val startedAt by viewModel.startedAtElapsed.collectAsStateWithLifecycle()
    val playingId by viewModel.playingId.collectAsStateWithLifecycle()

    val snackbarHostState = remember { SnackbarHostState() }
    var hasMic by remember { mutableStateOf(AppPermissions.hasMic(context)) }
    var hasBle by remember { mutableStateOf(AppPermissions.hasBle(context)) }

    val micLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        hasMic = granted
        if (!granted) {
            scope.launch {
                snackbarHostState.showSnackbar("Microphone access is needed to record")
            }
        }
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                hasMic = AppPermissions.hasMic(context)
                hasBle = AppPermissions.hasBle(context)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    LaunchedEffect(hasBle) {
        if (hasBle) MeshForegroundService.start(context)
    }
    LaunchedEffect(viewModel) {
        viewModel.messages.collect { snackbarHostState.showSnackbar(it) }
    }
    DisposableEffect(viewModel) {
        onDispose { viewModel.stopPlayback() }
    }

    var elapsedMs by remember { mutableLongStateOf(0L) }
    LaunchedEffect(startedAt) {
        val start = startedAt
        if (start == null) {
            elapsedMs = 0L
            return@LaunchedEffect
        }
        while (true) {
            elapsedMs = graph.recordingElapsedMs(start)
            delay(100L)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Nearby")
                        Text(
                            text = peerSummary(visiblePeers.size, settings.discoverable),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Outlined.Settings, contentDescription = "Settings")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        bottomBar = {
            Column {
                TalkBar(
                    isRecording = isRecording,
                    elapsedMs = elapsedMs,
                    amplitude = amplitude,
                    hasMic = hasMic,
                    onStart = {
                        if (AppPermissions.hasMic(context)) {
                            hasMic = true
                            viewModel.startRecording()
                        } else {
                            micLauncher.launch(Manifest.permission.RECORD_AUDIO)
                        }
                    },
                    onStop = viewModel::stopRecording,
                    navigationPadding = false,
                )
                bottomBar()
            }
        },
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item {
                PermissionCard(
                    onPermissionsChanged = {
                        hasMic = AppPermissions.hasMic(context)
                        hasBle = AppPermissions.hasBle(context)
                    },
                )
            }

            item {
                IdentityCard(
                    nickname = settings.displayName,
                    fingerprint = fingerprint,
                    discoverable = settings.discoverable,
                )
            }

            item {
                Text(
                    text = "Nearby phones",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }

            if (visiblePeers.isEmpty()) {
                item {
                    Text(
                        text = "No one yet. Keep the app open or share a private channel by QR.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                items(visiblePeers, key = { it.fingerprint }) { peer ->
                    PeerRow(
                        peer = peer,
                        muted = peer.fingerprint in muted,
                        onMute = { graph.peerPrefs.setMuted(peer.fingerprint, peer.fingerprint !in muted) },
                        onBlock = {
                            graph.peerPrefs.setBlocked(peer.fingerprint, true)
                            graph.peerPrefs.setMuted(peer.fingerprint, false)
                        },
                    )
                }
            }

            if (blocked.isNotEmpty()) {
                item {
                    TextButton(onClick = { blocked.forEach { graph.peerPrefs.setBlocked(it, false) } }) {
                        Text("Unblock ${blocked.size} hidden peer" + if (blocked.size == 1) "" else "s")
                    }
                }
            }

            item {
                Text(
                    text = "Public feed",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(top = 10.dp),
                )
            }

            if (visibleNotes.isEmpty()) {
                item {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 28.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.GraphicEq,
                            contentDescription = null,
                            modifier = Modifier.size(48.dp),
                            tint = MaterialTheme.colorScheme.primary,
                        )
                        Spacer(Modifier.height(10.dp))
                        Text("No nearby clips yet", style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "Hold the button below to say something. Anyone in range hears it.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            } else {
                items(visibleNotes, key = { it.id }) { note ->
                    VoiceNoteCard(
                        note = note,
                        isPlaying = playingId == note.id,
                        onPlay = { viewModel.togglePlayback(note) },
                        showFingerprint = true,
                    )
                }
            }
        }
    }
}

private fun peerSummary(count: Int, discoverable: Boolean): String {
    val peers = when (count) {
        0 -> "No peers in range"
        1 -> "1 peer in range"
        else -> "$count peers in range"
    }
    return "$peers · " + if (discoverable) "discoverable" else "hidden"
}

@Composable
private fun IdentityCard(
    nickname: String,
    fingerprint: String,
    discoverable: Boolean,
) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer,
            contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Outlined.Person, contentDescription = null)
            Spacer(Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "You are $nickname#" + fingerprint.ifBlank { "------" },
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = if (discoverable) {
                        "Discoverable on the public nearby channel"
                    } else {
                        "Hidden: you can hear others but are not announced"
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun PeerRow(
    peer: NearbyPeer,
    muted: Boolean,
    onMute: () -> Unit,
    onBlock: () -> Unit,
) {
    var menuOpen by remember { mutableStateOf(false) }
    Card {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 12.dp, top = 10.dp, bottom = 10.dp, end = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Surface(
                shape = CircleShape,
                color = MaterialTheme.colorScheme.primaryContainer,
                contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                modifier = Modifier.size(40.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(Icons.Outlined.NearMe, contentDescription = null, modifier = Modifier.size(20.dp))
                }
            }
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "${peer.nickname}#${peer.fingerprint}",
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SignalBars(rssi = peer.rssi, direct = peer.isDirect)
                    Spacer(Modifier.width(6.dp))
                    Text(
                        text = if (peer.isDirect) "Direct" else "${peer.hopCount} hops",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (muted) {
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = "Muted",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }
            Box {
                IconButton(onClick = { menuOpen = true }) {
                    Icon(Icons.Filled.MoreVert, contentDescription = "Peer actions")
                }
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    DropdownMenuItem(
                        text = { Text(if (muted) "Unmute" else "Mute") },
                        onClick = {
                            menuOpen = false
                            onMute()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("Block") },
                        onClick = {
                            menuOpen = false
                            onBlock()
                        },
                    )
                }
            }
        }
    }
}

/** Four bars for direct neighbours; relays show a weaker two-bar hint. */
@Composable
private fun SignalBars(rssi: Int?, direct: Boolean) {
    val active = when {
        !direct -> 2
        rssi == null -> 3
        rssi >= -55 -> 4
        rssi >= -67 -> 3
        rssi >= -75 -> 2
        else -> 1
    }
    val activeColor = MaterialTheme.colorScheme.primary
    val idleColor = MaterialTheme.colorScheme.outlineVariant
    Row(
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        repeat(4) { index ->
            Box(
                modifier = Modifier
                    .width(3.dp)
                    .height((5 + index * 3).dp)
                    .background(
                        color = if (index < active) activeColor else idleColor,
                        shape = RoundedCornerShape(1.dp),
                    ),
            )
        }
    }
}
