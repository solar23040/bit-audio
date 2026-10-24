package com.solar23040.bitaudio.ui

import androidx.compose.runtime.Composable
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.solar23040.bitaudio.AppGraph
import com.solar23040.bitaudio.ui.screens.ChannelListScreen
import com.solar23040.bitaudio.ui.screens.ChannelScreen
import com.solar23040.bitaudio.ui.screens.JoinChannelScreen
import com.solar23040.bitaudio.ui.screens.SettingsScreen

private object Routes {
    const val CHANNELS = "channels"
    const val JOIN = "join"
    const val SETTINGS = "settings"
    const val CHANNEL = "channel/{channelId}"
    const val CHANNEL_ID = "channelId"

    fun channel(id: String): String = "channel/$id"
}

@Composable
fun AppNavHost(graph: AppGraph) {
    val navController = rememberNavController()

    NavHost(navController = navController, startDestination = Routes.CHANNELS) {
        composable(Routes.CHANNELS) {
            ChannelListScreen(
                graph = graph,
                onOpenChannel = { channelId -> navController.navigate(Routes.channel(channelId)) },
                onJoinChannel = { navController.navigate(Routes.JOIN) },
                onOpenSettings = { navController.navigate(Routes.SETTINGS) },
            )
        }
        composable(Routes.JOIN) {
            JoinChannelScreen(
                graph = graph,
                onBack = { navController.popBackStack() },
                onJoined = { channel ->
                    navController.popBackStack()
                    navController.navigate(Routes.channel(channel.id)) {
                        launchSingleTop = true
                    }
                },
            )
        }
        composable(
            route = Routes.CHANNEL,
            arguments = listOf(navArgument(Routes.CHANNEL_ID) { type = NavType.StringType }),
        ) { entry ->
            val channelId = entry.arguments?.getString(Routes.CHANNEL_ID) ?: return@composable
            ChannelScreen(
                graph = graph,
                channelId = channelId,
                onBack = { navController.popBackStack() },
            )
        }
        composable(Routes.SETTINGS) {
            SettingsScreen(
                graph = graph,
                onBack = { navController.popBackStack() },
            )
        }
    }
}
