import 'package:flutter_test/flutter_test.dart';
import 'package:yono_shield/main.dart';

void main() {
  testWidgets('YONO Shield app renders dashboard', (WidgetTester tester) async {
    await tester.pumpWidget(const YonoShieldApp());

    // Verify the app title appears
    expect(find.text('YONO SHIELD'), findsOneWidget);

    // Verify the ACTIVE status indicator text appears
    expect(find.text('ACTIVE'), findsOneWidget);

    // Verify bottom nav items appear
    expect(find.text('RADAR'), findsOneWidget);
    expect(find.text('SMS'), findsOneWidget);
    expect(find.text('OVERLAY'), findsOneWidget);
  });
}
