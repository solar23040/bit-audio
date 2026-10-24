package com.solar23040.bitaudio

import android.app.Application

class BitAudioApplication : Application() {
    lateinit var graph: AppGraph
        private set

    override fun onCreate() {
        super.onCreate()
        graph = AppGraph(this)
    }
}
