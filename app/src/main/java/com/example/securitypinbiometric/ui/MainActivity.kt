package com.example.securitypinbiometric.ui

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import com.example.securityauth.ui.pin.PinCodeFragment
import com.example.securitypinbiometric.R

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction()
                .replace(R.id.container, PinCodeFragment.newInstance())
                .commitNow()
        }
    }
}