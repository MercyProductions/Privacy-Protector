#pragma once
#include <string>

namespace Widgets {

class ProgressBar {
public:
    // Horizontal gradient progress bar
    static void RenderBar(float fraction, float width = -1.0f, float height = 8.0f, const char* overlay = nullptr);
    
    // Circular readiness score display
    static void RenderCircularScore(int score, float radius = 60.0f, const char* label = "READINESS");
    
    // Animated scanning/loading indicator
    static void RenderSpinner(float radius = 12.0f);
};

} // namespace Widgets
